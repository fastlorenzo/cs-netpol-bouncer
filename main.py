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
if not CROWDSEC_API_ADDRESS:
    raise ValueError("CROWDSEC_API_ADDRESS environment variable is required")
if not NETPOL_NAME:
    raise ValueError("NETPOL_NAME environment variable is required")
if not NETPOL_NAMESPACE:
    raise ValueError("NETPOL_NAMESPACE environment variable is required")

if USE_TLS and not os.path.exists(CERTIFICATES_PATH):
    # path not found error
    raise FileNotFoundError(f"CERTIFICATES_PATH {CERTIFICATES_PATH} does not exist")

SCHEME = "https" if USE_TLS else "http"

# Create logger
if os.environ.get("DEBUG", "false").lower() in ["true", "1", "t"]:
    logging.basicConfig(level=logging.DEBUG)
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


def update_netpol(ips):
    """
    Update the NetworkPolicy to match the list of IPs
    """
    try:
        netpol = networking_v1.read_namespaced_network_policy(
            NETPOL_NAME, NETPOL_NAMESPACE
        )
        log.debug(netpol)
        log.debug(netpol.spec)
        log.debug(netpol.spec.ingress)
        log.debug(netpol.spec.ingress[0])
        # Get the existing IPBlock
        ip_block = netpol.spec.ingress[0]._from[0].ip_block._except
        # Update the IPBlock
        ip_block = ips
        # Update the NetworkPolicy
        netpol.spec.ingress[0]._from[0].ip_block._except = ip_block
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
            # Get the list of IPs from the decisions
            log.debug("Decisions: %s", decisions)
            ips = [decision["value"] for decision in decisions]
            # Clean the list (remove duplicates and sort it)
            ips = list(set(ips))
            # remove ipv6 addresses
            ips = [ip for ip in ips if ":" not in ip]
            # Make the IP to be in CIDR format (if not already)
            ips = [ip + "/32" if "/" not in ip else ip for ip in ips]
            # Update the NetworkPolicy
            update_netpol(ips)
        # Wait for the next check interval
        log.debug("Waiting %s seconds before next check", CHECK_INTERVAL)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
