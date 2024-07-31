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
    if (*output == NULL) return -1;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)*output, &len, (unsigned char *)input, input_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)*output + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    fprintf(stderr, "Encrypted message: ");
    for (int i = 0; i < ciphertext_len; i++) {
        fprintf(stderr, "%02x", (unsigned char)(*output)[i]);
    }
    fprintf(stderr, "\n");

    return ciphertext_len;
}

static int decrypt_message(const char *input, int input_len, char **output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    fprintf(stderr, "Decrypting message: ");
    for (int i = 0; i < input_len; i++) {
        fprintf(stderr, "%02x", (unsigned char)input[i]);
    }
    fprintf(stderr, "\n");

    *output = (char *)malloc(input_len);
    if (*output == NULL) return -1;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)*output, &len, (unsigned char *)input, input_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)*output + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    (*output)[plaintext_len] = '\0';

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
    mosquitto_callback_register(mosquitto_id, MOSQ_EVT_MESSAGE, mosquitto_message_publish_callback, userdata, NULL);
    mosquitto_callback_register(mosquitto_id, MOSQ_EVT_MESSAGE, mosquitto_message_receive_callback, userdata, NULL);
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
mosquitto_message_publish_callbackstatic int (int event, void *userdata, void *message) {
    struct mosquitto_message *msg = (struct mosquitto_message *)message;
    fprintf(stderr, "Publishing message: %s\n", (char *)msg->payload);

    char *encrypted_msg;
    int encrypted_len = encrypt_message(msg->payload, msg->payloadlen, &encrypted_msg);
    if (encrypted_len < 0) {
        return MOSQ_ERR_UNKNOWN;
    }

    // Publish the encrypted message
    int result = mosquitto_publish((struct mosquitto *)userdata, NULL, msg->topic, encrypted_len, encrypted_msg, msg->qos, msg->retain);

    // Free the allocated memory
    free(encrypted_msg);

    return result;
}

static int mosquitto_message_receive_callback(int event, void *userdata, void *message) {
    struct mosquitto_message *msg = (struct mosquitto_message *)message;
    fprintf(stderr, "Receiving message: ");
    for (int i = 0; i < msg->payloadlen; i++) {
        fprintf(stderr, "%02x", (unsigned char)((char *)msg->payload)[i]);
    }
    fprintf(stderr, "\n");

    char *decrypted_msg;
    int decrypted_len = decrypt_message(msg->payload, msg->payloadlen, &decrypted_msg);
    if (decrypted_len < 0) {
        return MOSQ_ERR_UNKNOWN;
    }

    // Free the allocated memory
    free(decrypted_msg);

    return MOSQ_ERR_SUCCESS;
}
