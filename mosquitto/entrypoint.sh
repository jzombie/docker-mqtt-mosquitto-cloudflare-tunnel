#!/bin/sh

set -e

# Ensure GOCRYPT_PASSWORD is set
if [ -z "$GOCRYPT_PASSWORD" ]; then
  echo "GOCRYPT_PASSWORD is not set. Exiting."
  exit 1
fi

# Initialize or mount the encrypted filesystem as the mosquitto user
su mosquitto -c "
if [ ! -f /encrypted/gocryptfs.conf ]; then
  echo \"Initializing encrypted filesystem\"
  if [ \"\$(ls -A /encrypted)\" ]; then
    echo \"Error: /encrypted directory is not empty. Cannot initialize.\"
    exit 1
  fi
  echo \"$GOCRYPT_PASSWORD\" | gocryptfs -init /encrypted
fi

echo \"Mounting encrypted filesystem\"
echo \"$GOCRYPT_PASSWORD\" | gocryptfs /encrypted /var/lib/mosquitto

# Debug: Check if gocryptfs is mounted
echo \"Checking if gocryptfs is mounted:\"
mount | grep gocryptfs || echo \"gocryptfs is not mounted\"
"

# Run Mosquitto as the mosquitto user
exec su mosquitto -c "mosquitto -c /mosquitto/config/mosquitto.conf"
