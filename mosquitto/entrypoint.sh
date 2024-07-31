#!/bin/sh

set -e

# Ensure ENCFS_PASSWORD is set
if [ -z "$ENCFS_PASSWORD" ]; then
  echo "ENCFS_PASSWORD is not set. Exiting."
  exit 1
fi

# Create directories for encrypted and decrypted data
mkdir -p /encrypted /var/lib/mosquitto

# Set restrictive permissions to the directories
# chmod 700 /encrypted /var/lib/mosquitto

# Initialize or mount the encrypted filesystem
# if [ ! -f /encrypted/.encfs6.xml ]; then
#   echo "Initializing encrypted filesystem"
#   echo "$ENCFS_PASSWORD" | encfs --standard --stdinpass /encrypted /var/lib/mosquitto --verbose
# else
#   echo "Mounting encrypted filesystem"
#   echo "$ENCFS_PASSWORD" | encfs --stdinpass /encrypted /var/lib/mosquitto --verbose
# fi

# # Debug: Check if encfs is mounted
# echo "Checking if encfs is mounted:"
# mount | grep encfs || echo "encfs is not mounted"

# Ensure the decrypted directory is owned by the mosquitto user and is writable
# chown -R mosquitto:mosquitto /var/lib/mosquitto
# chmod 700 /var/lib/mosquitto

# Debug: List files in decrypted and encrypted
echo "Contents of /var/lib/mosquitto:"
ls -la /var/lib/mosquitto

echo "Contents of /encrypted:"
ls -la /encrypted

# Run Mosquitto
exec mosquitto -c /mosquitto/config/mosquitto.conf
