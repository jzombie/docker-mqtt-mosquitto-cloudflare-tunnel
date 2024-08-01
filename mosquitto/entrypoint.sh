#!/bin/sh

set -e

# Ensure GOCRYPT_PASSWORD is set
if [ -z "$GOCRYPT_PASSWORD" ]; then
  echo "GOCRYPT_PASSWORD is not set. Exiting."
  exit 1
fi

# Create necessary directories
mkdir -p /encrypted /var/lib/mosquitto

# Adjust permissions for the mosquitto user before mounting
chown mosquitto:mosquitto /encrypted /var/lib/mosquitto
chmod 700 /encrypted /var/lib/mosquitto

# Debug: Check ownership and permissions before mounting
# echo "Ownership and permissions before mounting:"
# ls -ld /encrypted
# ls -ld /var/lib/mosquitto

# Initialize the encrypted filesystem if it hasn't been initialized
if [ ! -f /encrypted/gocryptfs.conf ]; then
  echo "Initializing encrypted filesystem"
  if [ "$(ls -A /encrypted)" ]; then
    echo "Error: /encrypted directory is not empty. Cannot initialize."
    exit 1
  fi
  su mosquitto -c "echo \"$GOCRYPT_PASSWORD\" | gocryptfs -init /encrypted"
fi

# Mount the encrypted filesystem as the mosquitto user
echo "Mounting encrypted filesystem"
su mosquitto -c "echo \"$GOCRYPT_PASSWORD\" | gocryptfs -allow_other /encrypted /var/lib/mosquitto"

# Debug: Check if gocryptfs is mounted
echo "Checking if gocryptfs is mounted:"
mount | grep gocryptfs || echo "gocryptfs is not mounted"

# Ensure correct ownership and permissions on the mounted directory
echo "Setting correct ownership and permissions on the mounted directory"
chown -R mosquitto:mosquitto /var/lib/mosquitto
chmod -R 700 /var/lib/mosquitto

# Debug: Check ownership and permissions after mounting
# echo "Ownership and permissions after mounting:"
# ls -ld /var/lib/mosquitto
# ls -ld /encrypted

# Debug: List contents of /var/lib/mosquitto to check if persistence file is present
echo "Contents of /var/lib/mosquitto:"
ls -l /var/lib/mosquitto || echo "Failed to list contents of /var/lib/mosquitto"

# Check if the persistence file exists
if [ ! -f /var/lib/mosquitto/mosquitto.db ]; then
  echo "Persistence file not found, creating test retained message"
  mosquitto_pub -h localhost -t test/topic -m "Test retained message" -r || echo "Failed to publish test retained message"
else
  echo "Persistence file found, skipping retained message creation"
fi

# List the contents of /var/lib/mosquitto again to check for the persistence file
echo "Contents of /var/lib/mosquitto after checking for persistence file:"
ls -l /var/lib/mosquitto

chmod 0700 /mosquitto/config/aclfile
chown mosquitto:mosquitto /mosquitto/config/aclfile

# Run Mosquitto as the mosquitto user
exec su mosquitto -c "mosquitto -c /mosquitto/config/mosquitto.conf"
