#!/bin/sh

set -e

# Ensure GOCYPH_PASSWORD is set
if [ -z "$GOCYPH_PASSWORD" ]; then
  echo "GOCYPH_PASSWORD is not set. Exiting."
  exit 1
fi

# Initialize or mount the encrypted filesystem
if [ ! -d /encrypted/gocryptfs.conf ]; then
  echo "Initializing encrypted filesystem"
  if [ "$(ls -A /encrypted)" ]; then
    echo "Error: /encrypted directory is not empty. Cannot initialize."
    exit 1
  fi
  echo "$GOCYPH_PASSWORD" | gocryptfs -init /encrypted
fi

echo "Mounting encrypted filesystem"
echo "$GOCYPH_PASSWORD" | gocryptfs /encrypted /var/lib/mosquitto

# Debug: Check if gocryptfs is mounted
echo "Checking if gocryptfs is mounted:"
mount | grep gocryptfs || echo "gocryptfs is not mounted"

# Run Mosquitto
exec mosquitto -c /mosquitto/config/mosquitto.conf
