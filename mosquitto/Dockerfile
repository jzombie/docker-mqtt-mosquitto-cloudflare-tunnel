FROM eclipse-mosquitto:latest

# Install dependencies
RUN apk update && \
    apk add --no-cache gcc musl-dev openssl-dev mosquitto-dev

# Copy plugin source code
COPY plugin/src /mosquitto/plugin/src

# Create build directory
RUN mkdir -p /mosquitto/plugin/build

# Compile the Mosquitto encryption plugin
RUN gcc -fPIC -shared -o /mosquitto/plugin/build/mosquitto_encryption_plugin.so \
    -I/usr/local/include -I/usr/include/openssl \
    /mosquitto/plugin/src/mosquitto_encryption_plugin.c \
    -lmosquitto -lssl -lcrypto

# Copy configuration files
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
COPY aclfile /mosquitto/config/aclfile
COPY entrypoint.sh /entrypoint.sh

# Ensure entrypoint script is executable
RUN chmod +x /entrypoint.sh

# Expose ports
EXPOSE 1883 9001

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
