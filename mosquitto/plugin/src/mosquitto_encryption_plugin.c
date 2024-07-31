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
static int mosquitto_message_save_callback(int event, void *userdata, struct mosquitto_evt_message *msg);
static int mosquitto_message_load_callback(int event, void *userdata, struct mosquitto_evt_message *msg);

static int encrypt_message(const char *input, int input_len, char **output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (input_len == 0) {
        *output = malloc(1);
        if (!*output) return -1;
        (*output)[0] = '\0';
        return 0;
    }

    *output = malloc(input_len + AES_BLOCK_SIZE);
    if (!*output) return -1;

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
    return ciphertext_len;
}

static int decrypt_message(const char *input, int input_len, char **output) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (input_len == 0) {
        *output = malloc(1);
        if (!*output) return -1;
        (*output)[0] = '\0';
        return 0;
    }

    *output = malloc(input_len + AES_BLOCK_SIZE);
    if (!*output) return -1;

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
    return plaintext_len;
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
    return MOSQ_PLUGIN_VERSION;
}

static mosquitto_plugin_id_t *mosquitto_id;

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count) {
    fprintf(stderr, "Plugin initialized\n");
    mosquitto_id = identifier;

    int rc = mosquitto_callback_register(mosquitto_id, MOSQ_EVT_MESSAGE, (MOSQ_FUNC_generic_callback)mosquitto_message_save_callback, NULL, userdata);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Failed to register save callback: %d\n", rc);
        return rc;
    }

    rc = mosquitto_callback_register(mosquitto_id, MOSQ_EVT_MESSAGE, (MOSQ_FUNC_generic_callback)mosquitto_message_load_callback, NULL, userdata);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Failed to register load callback: %d\n", rc);
        return rc;
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

static int mosquitto_message_save_callback(int event, void *userdata, struct mosquitto_evt_message *msg) {
    fprintf(stderr, "mosquitto_message_save_callback triggered\n");

    if (!msg || !msg->payload) {
        fprintf(stderr, "Invalid message pointer or payload is NULL\n");
        return MOSQ_ERR_UNKNOWN;
    }

    char *encrypted_msg = NULL;
    int encrypted_len = encrypt_message(msg->payload, msg->payloadlen, &encrypted_msg);
    if (encrypted_len < 0) {
        fprintf(stderr, "Encryption failed\n");
        return MOSQ_ERR_UNKNOWN;
    }

    msg->payload = encrypted_msg;
    msg->payloadlen = encrypted_len;

    fprintf(stderr, "Message encrypted for saving: %.*s\n", msg->payloadlen, (char *)msg->payload);
    free(encrypted_msg);
    return MOSQ_ERR_SUCCESS;
}

static int mosquitto_message_load_callback(int event, void *userdata, struct mosquitto_evt_message *msg) {
    fprintf(stderr, "mosquitto_message_load_callback triggered\n");

    if (!msg || !msg->payload) {
        fprintf(stderr, "Invalid message pointer or payload is NULL\n");
        return MOSQ_ERR_UNKNOWN;
    }

    char *decrypted_msg = NULL;
    int decrypted_len = decrypt_message(msg->payload, msg->payloadlen, &decrypted_msg);
    if (decrypted_len < 0) {
        fprintf(stderr, "Decryption failed\n");
        return MOSQ_ERR_UNKNOWN;
    }

    msg->payload = decrypted_msg;
    msg->payloadlen = decrypted_len;

    fprintf(stderr, "Message decrypted after loading: %.*s\n", msg->payloadlen, (char *)msg->payload);
    free(decrypted_msg);
    return MOSQ_ERR_SUCCESS;
}
