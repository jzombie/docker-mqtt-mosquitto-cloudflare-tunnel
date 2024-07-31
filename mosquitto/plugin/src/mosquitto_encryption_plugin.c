#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16

const unsigned char key[AES_KEY_SIZE / 8] = "01234567890123456789012345678901";
const unsigned char iv[AES_BLOCK_SIZE] = "0123456789012345";

static int encrypt_message(const char *input, int input_len, char **output);
static int decrypt_message(const char *input, int input_len, char **output);
static int mosquitto_message_publish_callback(int event, void *userdata, void *message);
static int mosquitto_message_receive_callback(int event, void *userdata, void *message);

static int encrypt_message(const char *input, int input_len, char **output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    fprintf(stderr, "Encrypting message: %s\n", input);

    *output = (char *)malloc(input_len + AES_BLOCK_SIZE);
    if (*output == NULL) {
        fprintf(stderr, "Failed to allocate memory for encryption\n");
        return -1;
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create cipher context\n");
        free(*output);
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Encryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)*output, &len, (unsigned char *)input, input_len)) {
        fprintf(stderr, "Encryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)*output + len, &len)) {
        fprintf(stderr, "Encryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    fprintf(stderr, "Encrypted message length: %d\n", ciphertext_len);
    return ciphertext_len;
}

static int decrypt_message(const char *input, int input_len, char **output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    fprintf(stderr, "Decrypting message with length: %d\n", input_len);

    *output = (char *)malloc(input_len + 1); // +1 for null terminator
    if (*output == NULL) {
        fprintf(stderr, "Failed to allocate memory for decryption\n");
        return -1;
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create cipher context\n");
        free(*output);
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Decryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)*output, &len, (unsigned char *)input, input_len)) {
        fprintf(stderr, "Decryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)*output + len, &len)) {
        fprintf(stderr, "Decryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    (*output)[plaintext_len] = '\0'; // Null-terminate the string

    fprintf(stderr, "Decrypted message: %s\n", *output);
    return plaintext_len;
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
    return MOSQ_PLUGIN_VERSION;
}

static mosquitto_plugin_id_t *mosquitto_id;

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count) {
    fprintf(stderr, "Plugin initialized\n");
    mosquitto_id = identifier;
    int rc;
    rc = mosquitto_callback_register(mosquitto_id, MOSQ_EVT_MESSAGE, mosquitto_message_publish_callback, userdata, NULL);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Failed to register publish callback: %d\n", rc);
    }
    rc = mosquitto_callback_register(mosquitto_id, MOSQ_EVT_MESSAGE, mosquitto_message_receive_callback, userdata, NULL);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Failed to register receive callback: %d\n", rc);
    }
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count) {
    fprintf(stderr, "Plugin cleaned up\n");
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_init(void **userdata, struct mosquitto_opt *options, int option_count) {
    fprintf(stderr, "Auth plugin initialized\n");
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count) {
    fprintf(stderr, "Auth plugin cleaned up\n");
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *userdata, struct mosquitto_opt *options, int option_count, bool reload) {
    fprintf(stderr, "Security initialized\n");
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *userdata, struct mosquitto_opt *options, int option_count, bool reload) {
    fprintf(stderr, "Security cleaned up\n");
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *userdata, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg) {
    fprintf(stderr, "ACL check\n");
    return MOSQ_ERR_SUCCESS;
}

// Define the callback functions with correct signatures
static int mosquitto_message_publish_callback(int event, void *userdata, void *message) {
    struct mosquitto_message *msg = (struct mosquitto_message *)message;
    fprintf(stderr, "mosquitto_message_publish_callback triggered\n");
    if (!msg || !msg->payload) {
        fprintf(stderr, "Invalid message or payload\n");
        return MOSQ_ERR_UNKNOWN;
    }
    fprintf(stderr, "Publishing message: %s\n", (char *)msg->payload);

    char *encrypted_msg = NULL;
    int encrypted_len = encrypt_message(msg->payload, msg->payloadlen, &encrypted_msg);
    if (encrypted_len < 0) {
        fprintf(stderr, "Encryption failed\n");
        return MOSQ_ERR_UNKNOWN;
    }

    // Log the encrypted message being sent
    fprintf(stderr, "Sending encrypted message: ");
    for (int i = 0; i < encrypted_len; i++) {
        fprintf(stderr, "%02x", (unsigned char)encrypted_msg[i]);
    }
    fprintf(stderr, "\n");

    // Publish the encrypted message
    int result = mosquitto_publish((struct mosquitto *)userdata, NULL, msg->topic, encrypted_len, encrypted_msg, msg->qos, msg->retain);
    if (result != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Failed to publish encrypted message: %d\n", result);
    }

    // Free the allocated memory
    free(encrypted_msg);

    fprintf(stderr, "Published encrypted message\n");
    return result;
}

static int mosquitto_message_receive_callback(int event, void *userdata, void *message) {
    struct mosquitto_message *msg = (struct mosquitto_message *)message;
    fprintf(stderr, "mosquitto_message_receive_callback triggered\n");
    if (!msg || !msg->payload) {
        fprintf(stderr, "Invalid message or payload\n");
        return MOSQ_ERR_UNKNOWN;
    }
    fprintf(stderr, "Receiving message: ");
    for (int i = 0; i < msg->payloadlen; i++) {
        fprintf(stderr, "%02x", (unsigned char)((char *)msg->payload)[i]);
    }
    fprintf(stderr, "\n");

    char *decrypted_msg = NULL;
    int decrypted_len = decrypt_message(msg->payload, msg->payloadlen, &decrypted_msg);
    if (decrypted_len < 0) {
        fprintf(stderr, "Decryption failed\n");
        return MOSQ_ERR_UNKNOWN;
    }

    fprintf(stderr, "Received and decrypted message: %s\n", decrypted_msg);
    // Free the allocated memory
    free(decrypted_msg);

    return MOSQ_ERR_SUCCESS;
}
