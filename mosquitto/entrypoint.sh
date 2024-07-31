#!/bin/sh

set -e

# Ensure ENCFS_PASSWORD is set
if [ -z "$ENCFS_PASSWORD" ]; then
  echo "ENCFS_PASSWORD is not set. Exiting."
  exit 1
fi

# Create necessary directories
mkdir -p /encrypted /config /var/lib/mosquitto
chmod 700 /encrypted /config /var/lib/mosquitto

# Function to initialize encrypted filesystem using expect
initialize_encfs() {
  expect -c "
  spawn su mosquitto -c \"encfs --standard --stdinpass /encrypted /var/lib/mosquitto --verbose\"
  expect {
    \"Enter EncFS password:\" {
      send \"$ENCFS_PASSWORD\r\"
      exp_continue
    }
    \"Verify EncFS password:\" {
      send \"$ENCFS_PASSWORD\r\"
      exp_continue
    }
    \"Please choose from one of the following options:\" {
      send \"\r\"
      exp_continue
    }
  }
  interact
  "
}

# Function to mount encrypted filesystem using expect
mount_encfs() {
  expect -c "
  spawn su mosquitto -c \"encfs --stdinpass /encrypted /var/lib/mosquitto --verbose\"
  expect {
    \"EncFS Password:\" {
      send \"$ENCFS_PASSWORD\r\"
      exp_continue
    }
    \"Please choose from one of the following options:\" {
      send \"\r\"
      exp_continue
    }
  }
  interact
  "
}

# Initialize or mount the encrypted filesystem
if [ ! -f /config/.encfs6.xml ]; then
  echo "Initializing encrypted filesystem"
  initialize_encfs
  # Move .encfs6.xml to the config directory
  mv /encrypted/.encfs6.xml /config/
  chmod 600 /config/.encfs6.xml
else
  echo "Mounting encrypted filesystem"
  mount_encfs
  chmod 600 /config/.encfs6.xml
fi

# Debug: Check if encfs is mounted
echo "Checking if encfs is mounted:"
mount | grep encfs || echo "encfs is not mounted"

# Debug: List files in /encrypted and /var/lib/mosquitto
echo "Contents of /encrypted:"
ls -la /encrypted

echo "Contents of /var/lib/mosquitto:"
ls -la /var/lib/mosquitto

# Ensure the directory is owned by the mosquitto user and is writable
chown -R mosquitto:mosquitto /var/lib/mosquitto
chmod 700 /var/lib/mosquitto

# Run Mosquitto
exec mosquitto -c /mosquitto/config/mosquitto.conf
