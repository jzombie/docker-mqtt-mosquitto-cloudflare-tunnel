# Start with an Alpine base image that supports FUSE
FROM alpine:latest

# Install necessary packages including FUSE, Mosquitto, and encfs
RUN apk update && \
    apk add --no-cache \
    bash \
    fuse \
    encfs \
    mosquitto \
    mosquitto-clients \
    shadow

# Create necessary directories and set permissions
RUN mkdir -p /encrypted /var/lib/mosquitto && \
    chown -R mosquitto:mosquitto /var/lib/mosquitto && \
    chmod -R 700 /var/lib/mosquitto && \
    chmod -R 700 /encrypted

# Ensure mosquitto user has a valid shell
RUN usermod -s /bin/bash mosquitto

# Copy the Mosquitto configuration files and entrypoint script
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
COPY aclfile /mosquitto/config/aclfile
COPY entrypoint.sh /entrypoint.sh

# Ensure entrypoint script is executable
RUN chmod +x /entrypoint.sh

# Expose Mosquitto ports
EXPOSE 1883 9001

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
