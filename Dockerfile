FROM alpine:3.7
LABEL maintainer="Lorenzo Bernardi <git@bernardi.be>"

# install python3
RUN apk add --no-cache python3-dev \
    && pip3 install --upgrade pip

# set working directory
WORKDIR /app

# copy and install requirements
COPY ./requirements.txt /app/requirements.txt
RUN pip3 install -r requirements.txt

# clean up
RUN rm -rf /var/cache/apk/* \
    && rm -rf /tmp/* \
    && rm -rf /root/.cache/*

# copy the content of the local src directory to the working directory
COPY . /app

# Create a user to run the app with home directory /app
RUN addgroup -S user && adduser -S user -G user
RUN chown -R user:user /app

# Switch to the user
USER user

CMD [ "python3", "main.py" ]
