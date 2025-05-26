#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>

#include <string.h>

#include "signature_handling.h"

const char* CONTEXT_BASED_AUTHENTICATION_SERVER_SIGNATURE_CERT = "-----BEGIN CERTIFICATE-----\n"
    "MIIBNTCB3KADAgECAhQNDJL7fKaY0xyv1xoyw54En+/n3jAKBggqhkjOPQQDAjAb\n"
    "MRkwFwYDVQQDDBByZW1vdGUtc2lnbmF0dXJlMB4XDTI1MDUyNDE5MDUyM1oXDTM1\n"
    "MDUyMjE5MDUyM1owGzEZMBcGA1UEAwwQcmVtb3RlLXNpZ25hdHVyZTBZMBMGByqG\n"
    "SM49AgEGCCqGSM49AwEHA0IABJI038LLU1+ePWVNls5uHWZ2I9p8Z36AsxKK00UD\n"
    "uvhGj78T2QlC9kkjfENtG8Onb1ta4xgzT333bRXi0oX5F+0wCgYIKoZIzj0EAwID\n"
    "SAAwRQIhANn2ipL5hbMsglvoAm4psNa9FvnKXe42k4zRbZIqOTzQAiAeOj7Y0YbO\n"
    "CVZVCoV0qM+gHm8Y2o4ypLU7CuO/oDRI7A==\n"
    "-----END CERTIFICATE-----\n";


TEE_Result verify_signature(const char* nonce, size_t nonce_size, const char* signature, size_t signature_size) {
    TEE_Result res;
    int ret;
    mbedtls_x509_crt cert;
    mbedtls_pk_context* pk;
    unsigned char hash[64];
    const mbedtls_md_info_t* md_info;

    mbedtls_x509_crt_init(&cert);

    ret = mbedtls_x509_crt_parse(
        &cert,
        (const unsigned char*) CONTEXT_BASED_AUTHENTICATION_SERVER_SIGNATURE_CERT,
        strlen(CONTEXT_BASED_AUTHENTICATION_SERVER_SIGNATURE_CERT) + 1
    );
    if (ret != 0) {
        res = TEE_ERROR_SECURITY;
        goto clean;
    }

    pk = &cert.pk;
    if (!mbedtls_pk_can_do(pk, MBEDTLS_PK_ECKEY)) {
        res = TEE_ERROR_SECURITY;
        goto clean;
    }

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md_info == NULL) {
        res = TEE_ERROR_SECURITY;
        goto clean;
    }

    ret = mbedtls_md(md_info, (const unsigned char*) nonce, nonce_size, hash);
    if (ret != 0) {
        res = TEE_ERROR_SECURITY;
        goto clean;
    }

    ret = mbedtls_pk_verify(
        pk, MBEDTLS_MD_SHA512,
        (const unsigned char*) hash, sizeof(hash),
        (const unsigned char*) signature, signature_size
    );
    if (ret != 0) {
        res = TEE_ERROR_EXTERNAL_CANCEL;
    } else {
        res = TEE_SUCCESS;
    }

clean:
    mbedtls_x509_crt_free(&cert);

    return res;
}
