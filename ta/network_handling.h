#ifndef TA_CONTEXT_BASED_AUTHENTICATION_NETWORK_HANDLING_H
#define TA_CONTEXT_BASED_AUTHENTICATION_NETWORK_HANDLING_H


#include <stdint.h>
#include <tee_internal_api.h>

#include <mbedtls/ssl.h>
#include <tee_isocket.h>

#include "certificate_handling.h"


struct socket_ctx {
    uint32_t handle;
    uint32_t proto_error;
};


int get_random_data_for_mbedtls(
    void* ctx __unused,
    unsigned char* output,
    size_t output_length
);


int wrapped_send(
    void* ctx,
    const unsigned char* buf,
    size_t len
);


int wrapped_recv(
    void* ctx,
    unsigned char* buf,
    size_t len
);


TEE_Result open_connection(
    TEE_iSocketHandle* tcp_ctx,
    mbedtls_ssl_config* ssl_conf,
    mbedtls_x509_crt* ca_cert,
    mbedtls_x509_crt* client_cert,
    mbedtls_pk_context* client_key,
    mbedtls_ssl_context* ssl_ctx,

    bool use_client_certificate
);


TEE_Result send_command_data(
    /* TEE_iSocketHandle tcp_ctx,
    mbedtls_ssl_config* ssl_conf,
    mbedtls_x509_crt* ca_cert,
    mbedtls_x509_crt* client_cert,
    mbedtls_pk_context* client_key, */
    mbedtls_ssl_context* ssl_ctx,

    const unsigned char* data,
    size_t data_length
);


TEE_Result wait_for_response(
    /*TEE_iSocketHandle tcp_ctx,
    mbedtls_ssl_config* ssl_conf,
    mbedtls_x509_crt* ca_cert,
    mbedtls_x509_crt* client_cert,
    mbedtls_pk_context* client_key, */
    mbedtls_ssl_context* ssl_ctx,

    unsigned char* buffer,
    size_t buffer_length
);


TEE_Result close_connection(
    TEE_iSocketHandle tcp_ctx,
    mbedtls_ssl_context* ssl_ctx
);


void clean_context(
    mbedtls_ssl_config* ssl_conf,
    mbedtls_x509_crt* ca_cert,
    mbedtls_x509_crt* client_cert,
    mbedtls_pk_context* client_key,
    mbedtls_ssl_context* ssl_ctx
);


TEE_Result execute_command(
    const unsigned char* command,
    uint16_t command_length,
    unsigned char* response_buffer,
    uint16_t response_buffer_length,
    bool use_client_certificate
);


#endif
