#include <string.h>

#include <tee_internal_api.h>

#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/base64.h>

#include "storage_handling.h"
#include "tee_api_defines.h"
#include "certificate_handling.h"
#include "network_handling.h"
#include "command_parser.h"


TEE_Result load_private_key_from_storage(mbedtls_pk_context* key) {
    TEE_Result res;
    char buffer[1024];
    TEE_MemFill(buffer, 0, sizeof(buffer));

    mbedtls_pk_init(key);

    res = read_object_if_exists(STORAGE_ID_PRIVATE_KEY, strlen(STORAGE_ID_PRIVATE_KEY), buffer, sizeof(buffer));
    if (res != TEE_SUCCESS)
        return res;
    buffer[1023] = '\0';

    if (mbedtls_pk_parse_key(key, (const unsigned char*) buffer, strlen(buffer) + 1, NULL, 0) != 0)
        return TEE_ERROR_BAD_FORMAT;

    return TEE_SUCCESS;
}


TEE_Result save_private_key_to_storage(mbedtls_pk_context* key) {
    char pem_buffer[1024];
    TEE_MemFill(pem_buffer, 0, sizeof(pem_buffer));

    if (mbedtls_pk_write_key_pem(key, (unsigned char*) pem_buffer, sizeof(pem_buffer)) != 0)
        return TEE_ERROR_SECURITY;

    return write_object(STORAGE_ID_PRIVATE_KEY, strlen(STORAGE_ID_PRIVATE_KEY), pem_buffer, strlen(pem_buffer) + 1);
}


TEE_Result load_client_cert_from_storage(mbedtls_x509_crt* crt) {
    TEE_Result res;
    char buffer[1024];
    TEE_MemFill(buffer, 0, sizeof(buffer));

    mbedtls_x509_crt_init(crt);

    res = read_object_if_exists(STORAGE_ID_CLIENT_CERT, strlen(STORAGE_ID_CLIENT_CERT), buffer, sizeof(buffer));
    if (res != TEE_SUCCESS)
        return res;

    buffer[1023] = '\0';

    if (mbedtls_x509_crt_parse(crt, (const unsigned char*) buffer, strlen(buffer) + 1) != 0)
        return TEE_ERROR_BAD_FORMAT;

    return TEE_SUCCESS;
}



TEE_Result save_client_certificate_to_storage(mbedtls_x509_crt* crt) {
    return write_object(STORAGE_ID_CLIENT_CERT, strlen(STORAGE_ID_CLIENT_CERT), (const char*) crt->raw.p, strlen((const char*) crt->raw.p) + 1);
}


TEE_Result generate_key(mbedtls_pk_context* key) {
    mbedtls_pk_init(key);

    if (mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
        return TEE_ERROR_SECURITY;

    if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*key), get_random_data_for_mbedtls, NULL) != 0)
        return TEE_ERROR_SECURITY;

    return TEE_SUCCESS;
}


TEE_Result get_subject_name(char* buffer, size_t buffer_length) {
    char id[4];
    char id_encoded[10];

    TEE_Result res = get_id(id);
    if (res != TEE_SUCCESS)
        return TEE_ERROR_BAD_FORMAT;

    size_t olen;
    int ret = mbedtls_base64_encode((unsigned char*) id_encoded, 10, &olen, (unsigned char*) id, 4);

    if (ret != 0)
        return ret;

    id_encoded[olen+1] = '\0';

    TEE_MemFill(buffer, 0, buffer_length);
    str_cat(buffer, "CN=", 3);
    str_cat(buffer, id_encoded, 9);

    return TEE_SUCCESS;
}


TEE_Result generate_csr(char* buffer, size_t buffer_length, mbedtls_pk_context* key) {
    int res;
    mbedtls_x509write_csr req;

    mbedtls_x509write_csr_init(&req);

    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&req, key);

    char subject_name[14];
    res = get_subject_name(subject_name, 14);
    if (res != TEE_SUCCESS)
        return res;

    res = mbedtls_x509write_csr_set_subject_name(&req, subject_name);
    if (res != 0)
        return TEE_ERROR_GENERIC;

    unsigned char buf[buffer_length];

    res = mbedtls_x509write_csr_pem(&req, buf, buffer_length, get_random_data_for_mbedtls, NULL);
    if (res != 0)
        return TEE_ERROR_GENERIC;

    TEE_MemMove(buffer, buf, buffer_length);

    mbedtls_x509write_csr_free(&req);

    return TEE_SUCCESS;
}


TEE_Result save_certificate_if_is_valid(char* pem_certificate) {
    TEE_Result res = TEE_SUCCESS;
    mbedtls_x509_crt cert;

    mbedtls_x509_crt_init(&cert);

    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char*) pem_certificate, strlen(pem_certificate) + 1);
    if (ret != 0)
        res = TEE_ERROR_BAD_FORMAT;
    else {
        res = write_object(STORAGE_ID_CLIENT_CERT, strlen(STORAGE_ID_CLIENT_CERT), pem_certificate, strlen(pem_certificate) + 1);
    }

    mbedtls_x509_crt_free(&cert);

    return res;
}


TEE_Result enroll_certificate(void) {
    TEE_Result res;

    char buffer[512];
    TEE_MemFill(buffer, 0, sizeof(buffer));

    mbedtls_pk_context key;
    generate_key(&key);

    res = generate_csr((char*) buffer, sizeof(buffer), &key);
    if (res != TEE_SUCCESS)
        return res;

    char command[512];
    TEE_MemFill(command, 0, sizeof(command));
    str_cat(command, "ENROLL\n", 7);
    str_cat(command, buffer, strlen(buffer));
    str_cat(command, "\n\n", 2);

    TEE_MemFill(buffer, 0, sizeof(buffer));
    res = execute_command(command, strlen(command), buffer, sizeof(buffer), false);
    if (res != TEE_SUCCESS)
        return res;
    uint16_t response_length = strlen(buffer);

    uint16_t offset = 0;
    char first_param[8];
    get_next_parameter(buffer, response_length, &offset, first_param, 8, NULL);

    if (first_param[0] != 'S')
        return TEE_ERROR_EXTERNAL_CANCEL;

    TEE_MemFill(command, 0, sizeof(command));
    join_parameters(buffer, response_length, offset, command, sizeof(command));
    offset = strlen(command);
    command[offset] = '\n';
    command[offset + 1] = '\0';

    res = save_certificate_if_is_valid(command);
    if (res != TEE_SUCCESS)
        return res;

    res = save_private_key_to_storage(&key);
    return res;
}
