#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>

#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16

const unsigned char key[AES_KEY_SIZE / 8] = "01234567890123456789012345678901";
const unsigned char iv[AES_BLOCK_SIZE] = "0123456789012345";

static int encrypt_message(const char *input, char *output, size_t output_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)output, &len, (unsigned char *)input, strlen(input))) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)output + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

static int decrypt_message(const char *input, char *output, size_t output_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)output, &len, (unsigned char *)input, strlen(input))) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)output + len, &len)) {
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

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_init(void **userdata, struct mosquitto_opt *options, int option_count) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *userdata, struct mosquitto_opt *options, int option_count, bool reload) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *userdata, struct mosquitto_opt *options, int option_count, bool reload) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *userdata, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg) {
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_message_publish(int event, void *userdata, struct mosquitto *mosq, const struct mosquitto_message *msg) {
    char encrypted_msg[256];
    int encrypted_len = encrypt_message(msg->payload, encrypted_msg, sizeof(encrypted_msg));
    if (encrypted_len < 0) {
        return MOSQ_ERR_UNKNOWN;
    }
    
    // Publish the encrypted message
    struct mosquitto_message encrypted_message = *msg;
    encrypted_message.payload = encrypted_msg;
    encrypted_message.payloadlen = encrypted_len;

    return mosquitto_publish(mosq, NULL, encrypted_message.topic, encrypted_message.payloadlen,
                             encrypted_message.payload, encrypted_message.qos, encrypted_message.retain);
}

int mosquitto_message_receive(int event, void *userdata, struct mosquitto *mosq, const struct mosquitto_message *msg) {
    char decrypted_msg[256];
    int decrypted_len = decrypt_message(msg->payload, decrypted_msg, sizeof(decrypted_msg));
    if (decrypted_len < 0) {
        return MOSQ_ERR_UNKNOWN;
    }

    // Create a new message with the decrypted payload
    struct mosquitto_message decrypted_message = *msg;
    decrypted_message.payload = decrypted_msg;
    decrypted_message.payloadlen = decrypted_len;

    // Re-publish the decrypted message
    return mosquitto_publish(mosq, NULL, decrypted_message.topic, decrypted_message.payloadlen,
                             decrypted_message.payload, decrypted_message.qos, decrypted_message.retain);
}
