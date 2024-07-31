CC = gcc
CFLAGS = -fPIC -shared -I/usr/local/include -I/usr/include/openssl
LDFLAGS = -L/usr/local/lib -lmosquitto -lssl -lcrypto

SRC_DIR = src
BUILD_DIR = build

TARGET = $(BUILD_DIR)/mosquitto_encryption_plugin.so

SRC = $(SRC_DIR)/mosquitto_encryption_plugin.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
