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
    mosquitto-dev \
    openssl-dev \
    gcc \
    musl-dev

# Create necessary directories
RUN mkdir -p /encrypted /var/lib/mosquitto

# Copy the Mosquitto configuration files and entrypoint script
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
COPY aclfile /mosquitto/config/aclfile
COPY entrypoint.sh /entrypoint.sh

# Set correct permissions and ownership
RUN chown -R mosquitto:mosquitto /var/lib/mosquitto && \
    chmod -R 700 /var/lib/mosquitto

# Ensure entrypoint script is executable
RUN chmod +x /entrypoint.sh

# Expose Mosquitto ports
EXPOSE 1883 9001

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
