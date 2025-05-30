#include <stdint.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_isocket.h>
#include <tee_tcpsocket.h>

#include <mbedtls/net_sockets.h>

#include "certificate_handling.h"
#include "network_handling.h"
#include "command_parser.h"
#include "tee_api_defines.h"


#define CONTEXT_BASED_AUTHENTICATION_SERVER_HOST   "192.168.42.1"
#define CONTEXT_BASED_AUTHENTICATION_SERVER_PORT   5432

const char* CONTEXT_BASED_AUTHENTICATION_SERVER_SSL_CERT = "-----BEGIN CERTIFICATE-----\n"
    "MIIBMzCB2qADAgECAhQFCKDlBtw8usO6W3/M5wcQYjwWyjAKBggqhkjOPQQDAjAa\n"
    "MRgwFgYDVQQDDA9yZW1vdGUtdmVyaWZpZXIwHhcNMjUwNTIxMTUxMjExWhcNMzUw\n"
    "NTE5MTUxMjExWjAaMRgwFgYDVQQDDA9yZW1vdGUtdmVyaWZpZXIwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAATVKksPRHnEI8GNtuU/HxZBucIx024G8orkm3hb3o6n\n"
    "dFxAJjiyJavmAffQwRPhp3/wjWCXwjoAqnwvr5TuFrn9MAoGCCqGSM49BAMCA0gA\n"
    "MEUCIQCdPw+DpsGPXnfWizWqU7efGQ+7bAmG4+xoDKcmxug8+wIgPSmRgy1GT72u\n"
    "MFvgxJKTXH9tBzeCfCEHRDAPnUi+CtA=\n"
    "-----END CERTIFICATE-----\n";



int get_random_data_for_mbedtls(void* ctx __unused, unsigned char* output, size_t output_length) {
    TEE_GenerateRandom(output, output_length);
    return 0;
}


int wrapped_send(void* ctx, const unsigned char* buf, size_t len) {
    uint32_t l = len;
    TEE_iSocketHandle ctx_conv = *(TEE_iSocketHandle*) ctx;
    TEE_Result res = TEE_tcpSocket->send(ctx_conv, buf, &l, 10000);

    if (res != TEE_SUCCESS)
        return MBEDTLS_ERR_NET_SEND_FAILED;

    return (int) l;
}


int wrapped_recv(void* ctx, unsigned char* buf, size_t len) {
    uint32_t l = len;
    TEE_iSocketHandle ctx_conv = *(TEE_iSocketHandle*) ctx;
    TEE_Result res = TEE_tcpSocket->recv(ctx_conv, buf, &l, 10000);

    if (res == TEE_ERROR_TIMEOUT)
        return MBEDTLS_ERR_SSL_TIMEOUT;
    else if (res != TEE_SUCCESS)
        return MBEDTLS_ERR_NET_RECV_FAILED;

    return (int) l;
}


TEE_Result open_connection(
    TEE_iSocketHandle *tcp_ctx, mbedtls_ssl_config* ssl_conf, mbedtls_x509_crt* ca_cert,
    mbedtls_x509_crt* client_cert, mbedtls_pk_context* client_key,
    mbedtls_ssl_context* ssl_ctx,
    bool use_client_certificate
) {
    TEE_Result res;
    int ret;
    uint32_t tcp_err;

    struct TEE_tcpSocket_Setup_s tcp_conf;
    tcp_conf.ipVersion = TEE_IP_VERSION_4;
    tcp_conf.server_addr = CONTEXT_BASED_AUTHENTICATION_SERVER_HOST;
    tcp_conf.server_port = CONTEXT_BASED_AUTHENTICATION_SERVER_PORT;

    mbedtls_ssl_init(ssl_ctx);
    mbedtls_ssl_config_init(ssl_conf);
    mbedtls_x509_crt_init(ca_cert);

    if (use_client_certificate) {
        res = load_private_key_from_storage(client_key);
        if (res != TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
        }
        res = load_client_cert_from_storage(client_cert);
        if (res != TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
        }
    }

    mbedtls_ssl_config_defaults(
        ssl_conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    mbedtls_ssl_conf_authmode(ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(ssl_conf, ca_cert, NULL);
    mbedtls_ssl_conf_rng(ssl_conf, get_random_data_for_mbedtls, NULL);
    mbedtls_ssl_conf_min_version(ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    if (use_client_certificate && mbedtls_ssl_conf_own_cert(ssl_conf, client_cert, client_key) != 0) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    mbedtls_ssl_setup(ssl_ctx, ssl_conf);
    mbedtls_ssl_set_bio(ssl_ctx, tcp_ctx, wrapped_send, wrapped_recv, NULL);

    ret = mbedtls_x509_crt_parse(ca_cert, (const unsigned char*) CONTEXT_BASED_AUTHENTICATION_SERVER_SSL_CERT, strlen(CONTEXT_BASED_AUTHENTICATION_SERVER_SSL_CERT) + 1);
    if (ret < 0)
        return TEE_ERROR_BAD_FORMAT;

    res = TEE_tcpSocket->open(tcp_ctx, &tcp_conf, &tcp_err);
    if (res != TEE_SUCCESS) {
        return res;
    }

    while ((ret = mbedtls_ssl_handshake(ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)  {
            return TEE_ERROR_BAD_FORMAT;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result send_command_data(mbedtls_ssl_context* ssl_ctx, const unsigned char* data, size_t data_length) {
    TEE_Result res;
    int ret;
    ret = mbedtls_ssl_write(ssl_ctx, data, data_length);
    if (ret < 0) {
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}


TEE_Result wait_for_response(mbedtls_ssl_context* ssl_ctx, unsigned char* buffer, size_t buffer_length) {
    int ret;
    TEE_Result res;
    uint16_t cumulatively_read = 0;
    char temp_buffer[512];
    unsigned char* current_write_position = buffer;
    while (cumulatively_read < buffer_length && !has_complete_command((const char*) buffer, buffer_length)) {
        ret = mbedtls_ssl_read(ssl_ctx, (unsigned char*) temp_buffer, 512);
        if (ret < 0) {
            return TEE_ERROR_BAD_STATE;
        }

        TEE_MemMove(
            current_write_position,
            temp_buffer,
            cumulatively_read + ret > buffer_length
                ? buffer_length - cumulatively_read - 1
                : ret
        );
        current_write_position += ret;
        cumulatively_read += ret;
    }
    buffer[buffer_length - 1] = '\0';

    return TEE_SUCCESS;
}

TEE_Result close_connection(TEE_iSocketHandle tcp_ctx, mbedtls_ssl_context* ssl_ctx) {
    mbedtls_ssl_close_notify(ssl_ctx);
    TEE_tcpSocket->close(tcp_ctx);

    return TEE_SUCCESS;
}

void clean_context(
    mbedtls_ssl_config* ssl_conf, mbedtls_x509_crt* ca_cert, mbedtls_x509_crt* client_cert, mbedtls_pk_context* client_key, mbedtls_ssl_context* ssl_ctx
) {
    if (ca_cert != NULL)
        mbedtls_x509_crt_free(ca_cert);
    if (client_cert != NULL)
        mbedtls_x509_crt_free(client_cert);
    if (client_key != NULL)
        mbedtls_pk_free(client_key);
    if (ssl_conf != NULL)
        mbedtls_ssl_config_free(ssl_conf);
    if (ssl_ctx != NULL)
        mbedtls_ssl_free(ssl_ctx);
}


/*TEE_Result execute_command(const char* command, uint16_t command_length, char* response_buffer, uint16_t response_buffer_length, uint8_t use_client_certificate) {
    TEE_Result res;
    int ret;
    uint32_t tcp_err;

    struct socket_ctx tcp_ctx;
    TEE_iSocketHandle tcp_ctx_c = (TEE_iSocketHandle) &tcp_ctx;

    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;

    struct TEE_tcpSocket_Setup_s tcp_conf;
    tcp_conf.ipVersion = TEE_IP_VERSION_4;
    tcp_conf.server_addr = CONTEXT_BASED_AUTHENTICATION_SERVER_HOST;
    tcp_conf.server_port = CONTEXT_BASED_AUTHENTICATION_SERVER_PORT;

    mbedtls_ssl_init(&ssl_ctx);
    mbedtls_ssl_config_init(&ssl_conf);
    mbedtls_x509_crt_init(&ca_cert);

    if (use_client_certificate) {
        res = load_private_key_from_storage(&client_key);
        if (res != TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
            goto clean_data;
        }
        res = load_client_cert_from_storage(&client_cert);
        if (res != TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
            goto clean_data;
        }
    }

    mbedtls_ssl_config_defaults(
        &ssl_conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &ca_cert, NULL);
    mbedtls_ssl_conf_rng(&ssl_conf, get_random_data_for_mbedtls, NULL);
    mbedtls_ssl_conf_min_version(&ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    if (use_client_certificate && mbedtls_ssl_conf_own_cert(&ssl_conf, &client_cert, &client_key) != 0) {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        goto clean_data;
    }

    mbedtls_ssl_setup(&ssl_ctx, &ssl_conf);
    mbedtls_ssl_set_bio(&ssl_ctx, &tcp_ctx_c, wrapped_send, wrapped_recv, NULL);

    ret = mbedtls_x509_crt_parse(&ca_cert, (const unsigned char*) CONTEXT_BASED_AUTHENTICATION_SERVER_SSL_CERT, strlen(CONTEXT_BASED_AUTHENTICATION_SERVER_SSL_CERT) + 1);
    if (ret < 0)
        return TEE_ERROR_BAD_FORMAT;

    res = TEE_tcpSocket->open(&tcp_ctx_c, &tcp_conf, &tcp_err);
    if (res != TEE_SUCCESS)
        goto clean;

    while ((ret = mbedtls_ssl_handshake(&ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)  {
            res = TEE_ERROR_BAD_FORMAT;
            goto clean;
        }
    }

    ret = mbedtls_ssl_write(&ssl_ctx, (const unsigned char*) command, command_length);
    if (ret < 0) {
        res = TEE_ERROR_BAD_STATE;
        goto clean;
    }

    uint16_t cumulatively_read = 0;
    char temp_buffer[512];
    char* current_write_position = response_buffer;
    while (cumulatively_read < response_buffer_length && !has_complete_command((const char*) response_buffer, response_buffer_length)) {
        ret = mbedtls_ssl_read(&ssl_ctx, (unsigned char*) temp_buffer, 512);
        if (ret < 0) {
            res = TEE_ERROR_BAD_STATE;
            goto clean;
        }

        TEE_MemMove(current_write_position, temp_buffer, cumulatively_read + ret > response_buffer_length ? response_buffer_length - cumulatively_read - 1 : ret);
        current_write_position += ret;
        cumulatively_read += ret;
    }

    mbedtls_ssl_close_notify(&ssl_ctx);
clean:
    TEE_tcpSocket->close(tcp_ctx_c);
clean_data:

    mbedtls_ssl_free(&ssl_ctx);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_x509_crt_free(&ca_cert);

    return res;
}*/


TEE_Result execute_command(const unsigned char* command, uint16_t command_length, unsigned char* response_buffer, uint16_t response_buffer_length, bool use_client_certificate) {
    TEE_Result res;

    struct socket_ctx tcp_ctx;
    TEE_iSocketHandle tcp_ctx_c;
    tcp_ctx_c = (TEE_iSocketHandle) &tcp_ctx;

    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
    mbedtls_ssl_context ssl_ctx;

    res = open_connection(
        &tcp_ctx_c, &ssl_conf, &ca_cert, &client_cert, &client_key, &ssl_ctx,
        use_client_certificate
    );
    if (res != TEE_SUCCESS)
        goto clean;

    res = send_command_data(
        &ssl_ctx,
        command, command_length
    );
    if (res != TEE_SUCCESS)
        goto clean;

    res = wait_for_response(
        &ssl_ctx,
        response_buffer, response_buffer_length
    );
    if (res != TEE_SUCCESS)
        goto clean;

    res = close_connection(
        tcp_ctx_c, &ssl_ctx
    );

clean:
    if (use_client_certificate)
        clean_context(
            &ssl_conf, &ca_cert, &client_cert, &client_key, &ssl_ctx
        );
    else
        clean_context(
            &ssl_conf, &ca_cert, NULL, NULL, &ssl_ctx
        );

    return res;
}
