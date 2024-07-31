#!/bin/sh

set -e

# Ensure ENCFS_PASSWORD is set
if [ -z "$ENCFS_PASSWORD" ]; then
  echo "ENCFS_PASSWORD is not set. Exiting."
  exit 1
fi

# Initialize or mount the encrypted filesystem as the mosquitto user
if [ ! -f /encrypted/.encfs6.xml ]; then
  echo "Initializing encrypted filesystem"
  su mosquitto -c "echo \"$ENCFS_PASSWORD\" | encfs --standard --stdinpass /encrypted /var/lib/mosquitto --verbose"
else
  echo "Mounting encrypted filesystem"
  su mosquitto -c "echo \"$ENCFS_PASSWORD\" | encfs --stdinpass /encrypted /var/lib/mosquitto --verbose"
fi

# # Debug: Check if encfs is mounted
echo "Checking if encfs is mounted:"
mount | grep encfs || echo "encfs is not mounted"

# Move .encfs6.xml to the config directory
mv /encrypted/.encfs6.xml /config/

# Run Mosquitto
exec mosquitto -c /mosquitto/config/mosquitto.conf
