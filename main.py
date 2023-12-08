"""
CrowdSec bouncer to maintain a blocklist in a Kubernetes NetworkPolicy
"""

import logging
import time
import os
import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# Load the Kubernetes configuration
config.load_incluster_config()

# Create the API client
v1 = client.CoreV1Api()

# Create network policy API client
networking_v1 = client.NetworkingV1Api()

# Load the configurations from Environment Variables
CROWDSEC_API_KEY = os.environ.get("CROWDSEC_API_KEY")
CROWDSEC_API_ADDRESS = os.environ.get("CROWDSEC_API_ADDRESS")
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", 60))
NETPOL_NAME = os.environ.get("NETPOL_NAME")
NETPOL_NAMESPACE = os.environ.get("NETPOL_NAMESPACE")

USE_TLS = os.environ.get("USE_TLS", "false").lower() in ["true", "1", "t"]
CERTIFICATES_PATH = os.environ.get("CERTIFICATES_PATH", "/etc/ssl/crowdsec-bouncer/")

# Check that all required environment variables have been set
if not CROWDSEC_API_KEY:
    raise ValueError("CROWDSEC_API_KEY environment variable is required")
if not CROWDSEC_API_URL:
    raise ValueError("CROWDSEC_API_URL environment variable is required")
if not NETPOL_NAME:
    raise ValueError("NETPOL_NAME environment variable is required")
if not NETPOL_NAMESPACE:
    raise ValueError("NETPOL_NAMESPACE environment variable is required")

if USE_TLS and not os.path.exists(CERTIFICATES_PATH):
    # path not found error
    raise FileNotFoundError(f"CERTIFICATES_PATH {CERTIFICATES_PATH} does not exist")

SCHEME = "https" if USE_TLS else "http"

# Create logger
log = logging.getLogger("cs-netpol-bouncer")


def get_decisions():
    """
    Get the decisions from the CrowdSec API
    """
    try:
        # use client certificates if tls is enabled (tls.crt, tls.key and ca.crt)
        if USE_TLS:
            response = requests.get(
                f"{SCHEME}://{CROWDSEC_API_ADDRESS}/v1/decisions",
                headers={"Authorization": "Bearer " + CROWDSEC_API_KEY},
                params={"type": "ban"},
                timeout=5,
                cert=(
                    os.path.join(CERTIFICATES_PATH, "tls.crt"),
                    os.path.join(CERTIFICATES_PATH, "tls.key"),
                ),
                verify=os.path.join(CERTIFICATES_PATH, "ca.crt"),
            )
        else:
            response = requests.get(
                f"{SCHEME}://{CROWDSEC_API_ADDRESS}/v1/decisions",
                headers={"Authorization": "Bearer " + CROWDSEC_API_KEY},
                params={"type": "ban"},
                timeout=5,
            )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        log.exception(err)
        return None


def get_netpol():
    """
    Get the NetworkPolicy from the Kubernetes API
    """
    try:
        return networking_v1.read_namespaced_network_policy(
            NETPOL_NAME, NETPOL_NAMESPACE
        )
    except ApiException as err:
        log.exception(err)
        return None


def update_netpol(netpol, ips):
    """
    Update the NetworkPolicy to match the list of IPs
    """
    try:
        # Get the existing IPBlock
        ip_block = netpol.spec.ingress[0].from_ip_blocks[0]
        # Update the IPBlock
        ip_block.cidr = ",".join(ips)
        # Update the NetworkPolicy
        netpol.spec.ingress[0].from_ip_blocks[0] = ip_block
        # Update the NetworkPolicy
        log.debug(
            "Updating NetworkPolicy %s in namespace %s",
            NETPOL_NAME,
            NETPOL_NAMESPACE,
        )
        log.debug("New banned IPs: %s", ips)
        return networking_v1.replace_namespaced_network_policy(
            NETPOL_NAME, NETPOL_NAMESPACE, netpol
        )
    except ApiException as err:
        log.exception(err)
        return None


def main():
    """
    Run the main loop to update the NetworkPolicy with the list of banned IPs
    from CrowdSec API every CHECK_INTERVAL seconds
    """
    while True:
        # Get the decisions from the CrowdSec API
        decisions = get_decisions()
        if decisions:
            # Get the NetworkPolicy from the Kubernetes API
            netpol = get_netpol()
            if netpol:
                # Get the list of IPs from the decisions
                ips = [decision["value"] for decision in decisions]
                # Update the NetworkPolicy
                update_netpol(netpol, ips)
        # Wait for the next check interval
        log.debug("Waiting %s seconds before next check", CHECK_INTERVAL)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
