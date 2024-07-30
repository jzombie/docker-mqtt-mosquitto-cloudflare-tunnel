#!/bin/sh
# Set permissions for the aclfile
chmod 0700 /mosquitto/config/aclfile

# Start the Mosquitto service
exec mosquitto -c /mosquitto/config/mosquitto.conf
