#!/bin/sh

# Set permissions for the aclfile
chmod 0700 /mosquitto/config/aclfile

# Ensure the persistence directory exists and set appropriate permissions
mkdir -p /var/lib/mosquitto
chown mosquitto:mosquitto /var/lib/mosquitto
chmod 0755 /var/lib/mosquitto

# Start the Mosquitto service
exec mosquitto -c /mosquitto/config/mosquitto.conf
