#include <stdbool.h>
#include <tee_internal_api.h>

#include <pta_csi.h>
#include <mbedtls/base64.h>

#include "context_based_authentication.h"
#include "csi_pta_wrapper.h"
#include "certificate_handling.h"
#include "signature_handling.h"
#include "network_handling.h"
#include "command_parser.h"
#include "storage_handling.h"
#include "utils.h"


#define TA_CONTEXT_BASED_AUTHENTICATION_BANDWIDTH               20      // either 20, 40, or 80 MHz
#define TA_CONTEXT_BASED_AUTHENTICATION_WIFI_CHANNEL            11      // must be a valid WiFi channel
#define TA_CONTEXT_BASED_AUTHENTICATION_RECORDING_TIMEOUT       60
#define TA_CONTEXT_BASED_AUTHENTICATION_SAMPLES_PER_DEVICE      128


#define TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME         "mac_filter"
#define TA_CONTEXT_BASED_AUTHENTICATION_CSI_HEADER_SIZE         1 + 6 + 2 + 2

uint16_t csi_data_size_per_sample() {
    uint8_t factor;
    switch (TA_CONTEXT_BASED_AUTHENTICATION_BANDWIDTH) {
        case 20:
            factor = 1;
            break;
        case 40:
            factor = 2;
            break;
        case 80:
            factor = 4;
            break;
        default:
            factor = 0;
    }

    return TA_CONTEXT_BASED_AUTHENTICATION_CSI_HEADER_SIZE + 256 * factor;
}

TEE_Result enroll_csi_data() {
    TEE_Result res;

    uint8_t available = false;
    uint8_t return_reason;
    uint32_t num_samples_collected;
    char cmd_buffer[2048];
    uint8_t csi_buffer[1042];

    struct socket_ctx ctx;
    TEE_iSocketHandle tcp_ctx;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
    mbedtls_ssl_context ssl_ctx;

    tcp_ctx = (TEE_iSocketHandle) &ctx;

    res = zero_all();
    if (res != TEE_SUCCESS)
        return res;
    res = disable_mac_filter();
    if (res != TEE_SUCCESS)
        return res;
    res = set_recording_parameters_and_start(
        TA_CONTEXT_BASED_AUTHENTICATION_WIFI_CHANNEL,
        TA_CONTEXT_BASED_AUTHENTICATION_BANDWIDTH,
        TA_CONTEXT_BASED_AUTHENTICATION_RECORDING_TIMEOUT,
        TA_CONTEXT_BASED_AUTHENTICATION_SAMPLES_PER_DEVICE
    );
    if (res != TEE_SUCCESS)
        return res;

    while (!available) {
        res = check_if_response_available(&available, &return_reason, &num_samples_collected);
        if (res != TEE_SUCCESS)
            return res;

        if (!available)
            TEE_Wait(500);
    }

    if (return_reason < 6 || return_reason > 9)
        return TEE_ERROR_CANCEL;

    res = open_connection(
        &tcp_ctx, &ssl_conf, &ca_cert, &client_cert, &client_key, &ssl_ctx,
        true
    );
    if (res != TEE_SUCCESS)
        goto clean;

    TEE_MemFill(cmd_buffer, 0, sizeof(cmd_buffer));
    str_cat(cmd_buffer, "ENROLL_CSI\n", 11);

    res = send_command_data(&ssl_ctx, (const unsigned char*) cmd_buffer, strlen(cmd_buffer));
    if (res != TEE_SUCCESS)
        goto close;

    uint16_t single_sample_size;
    uint32_t offset;
    uint32_t actually_read;
    size_t actually_written;
    int ret;

    offset = 0;
    single_sample_size = csi_data_size_per_sample();
    for (uint32_t i = 0; i < num_samples_collected; i++) {
        res = read_data(csi_buffer, single_sample_size, offset, &actually_read);
        if (res != TEE_SUCCESS)
            return res;
        if (actually_read <= 0)
            break;
        offset += actually_read;

        TEE_MemFill(cmd_buffer, 0, sizeof(cmd_buffer));
        ret = mbedtls_base64_encode(
            (unsigned char*) cmd_buffer, sizeof(cmd_buffer),
            &actually_written,
            csi_buffer, actually_read
        );
        if (ret != 0) {
            res = TEE_ERROR_BAD_STATE;
            goto close;
        }
        cmd_buffer[actually_written] = '\n';
        cmd_buffer[actually_written+1] = '\0';

        res = send_command_data(
            &ssl_ctx,
            (const unsigned char*) cmd_buffer, actually_written + 1
        );
        if (res != TEE_SUCCESS)
            goto close;
    }

    cmd_buffer[0] = '\n';
    cmd_buffer[1] = '\0';
    res = send_command_data(&ssl_ctx, (unsigned char*) cmd_buffer, 1);
    if (res != TEE_SUCCESS)
        goto close;

    res = wait_for_response(&ssl_ctx, (unsigned char*) cmd_buffer, sizeof(cmd_buffer));
    close_connection(tcp_ctx, &ssl_ctx);
    if (res != TEE_SUCCESS)
        goto clean;

    if (count_params(cmd_buffer, sizeof(cmd_buffer), 0) < 2) {
        res = TEE_ERROR_BAD_FORMAT;
        goto clean;
    }

    char param_buffer[512];
    offset = 0;
    if (get_next_parameter(cmd_buffer, sizeof(cmd_buffer), (uint16_t*) &offset, param_buffer, sizeof(param_buffer), NULL) != 0) {
        res = TEE_ERROR_BAD_FORMAT;
        goto clean;
    }

    if (param_buffer[0] != 'S') {
        res = TEE_ERROR_EXTERNAL_CANCEL;
        goto clean;
    }

    size_t output_buffer_offset;
    output_buffer_offset = 0;
    if (get_next_parameter(cmd_buffer, sizeof(cmd_buffer), (uint16_t*) &offset, param_buffer, sizeof(param_buffer), (uint16_t*) &output_buffer_offset) != 0) {
        res = TEE_ERROR_BAD_FORMAT;
        goto clean;
    }

    if (param_buffer[0] != '?') {
        ret = mbedtls_base64_decode((unsigned char*) cmd_buffer, sizeof(cmd_buffer), &actually_written, (const unsigned char*) param_buffer, output_buffer_offset);
        if (ret != 0) {
            res = TEE_ERROR_BAD_STATE;
            goto clean;
        }

        res = write_object(TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME, strlen(TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME), cmd_buffer, actually_written);
        if (res != TEE_SUCCESS) {
            goto clean;
        }
    }

    res = TEE_SUCCESS;
    goto clean;

close:
    close_connection(tcp_ctx, &ssl_ctx);

clean:
    clean_context(&ssl_conf, &ca_cert, &client_cert, &client_key, &ssl_ctx);

    return res;
}


TEE_Result create_prove(char* nonce, size_t nonce_size, char* signature_buffer, size_t signature_buffer_size, size_t* signature_size) {
    TEE_Result res;
    int ret;

    uint8_t available = false;
    uint8_t return_reason;
    uint32_t num_samples_collected;
    char cmd_buffer[2048];
    uint8_t csi_buffer[1042];
    uint8_t nonce_b64[64];
    uint8_t mac_buffer[300];
    size_t actually_written;
    size_t actually_read;
    uint16_t single_sample_size;
    uint32_t offset;

    struct socket_ctx ctx;
    TEE_iSocketHandle tcp_ctx;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
    mbedtls_ssl_context ssl_ctx;

    tcp_ctx = (TEE_iSocketHandle) &ctx;

    /* set command header */
    TEE_MemFill(cmd_buffer, 0, sizeof(cmd_buffer));
    str_cat(cmd_buffer, "PROVE\n", 6);
    ret = mbedtls_base64_encode((unsigned char*) nonce_b64, sizeof(nonce_b64), &actually_written, (const unsigned char*) nonce, nonce_size);
    if (ret != 0)
        return TEE_ERROR_BAD_STATE;
    str_cat(cmd_buffer, (const char*) nonce_b64, actually_written);
    str_cat(cmd_buffer, "\n", 1);

    /* set execution parameters */
    res = zero_all();
    if (res != TEE_SUCCESS)
        return res;

    if (object_exists(TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME, strlen(TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME)) == TEE_SUCCESS) {
        res = read_object_if_exists_with_length(
            TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME, strlen(TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME),
            (char*) mac_buffer, sizeof(mac_buffer),
            &actually_read
        );
        if (res != TEE_SUCCESS)
            return res;
        res = set_mac_filter(mac_buffer, actually_read / 6);
        if (res != TEE_SUCCESS)
            return res;
    } else {
        res = disable_mac_filter();
        if (res != TEE_SUCCESS)
            return res;
    }

    res = set_recording_parameters_and_start(
        TA_CONTEXT_BASED_AUTHENTICATION_WIFI_CHANNEL,
        TA_CONTEXT_BASED_AUTHENTICATION_BANDWIDTH,
        TA_CONTEXT_BASED_AUTHENTICATION_RECORDING_TIMEOUT,
        TA_CONTEXT_BASED_AUTHENTICATION_SAMPLES_PER_DEVICE
    );
    if (res != TEE_SUCCESS)
        return res;

    /* wait for data */
    while (!available) {
        res = check_if_response_available(&available, &return_reason, &num_samples_collected);
        if (res != TEE_SUCCESS)
            return res;

        if (!available)
            TEE_Wait(500);
    }

    if (return_reason < 6 || return_reason > 9)
        return TEE_ERROR_CANCEL;

    res = open_connection(
        &tcp_ctx, &ssl_conf, &ca_cert, &client_cert, &client_key, &ssl_ctx,
        true
    );
    if (res != TEE_SUCCESS)
        goto clean;


    res = send_command_data(&ssl_ctx, (const unsigned char*) cmd_buffer, strlen(cmd_buffer));
    if (res != TEE_SUCCESS)
        goto close;

    /* read & send data */
    offset = 0;
    single_sample_size = csi_data_size_per_sample();
    for (uint32_t i = 0; i < num_samples_collected; i++) {
        res = read_data(csi_buffer, single_sample_size, offset, (uint32_t*) &actually_read);
        if (res != TEE_SUCCESS)
            return res;
        if (actually_read <= 0)
            break;
        offset += actually_read;

        TEE_MemFill(cmd_buffer, 0, sizeof(cmd_buffer));
        ret = mbedtls_base64_encode(
            (unsigned char*) cmd_buffer, sizeof(cmd_buffer),
            &actually_written,
            csi_buffer, actually_read
        );
        if (ret != 0) {
            res = TEE_ERROR_BAD_STATE;
            goto close;
        }
        cmd_buffer[actually_written] = '\n';
        cmd_buffer[actually_written+1] = '\0';

        res = send_command_data(
            &ssl_ctx,
            (const unsigned char*) cmd_buffer, actually_written + 1
        );
        if (res != TEE_SUCCESS)
            goto close;
    }

    cmd_buffer[0] = '\n';
    cmd_buffer[1] = '\0';
    res = send_command_data(&ssl_ctx, (unsigned char*) cmd_buffer, 1);
    if (res != TEE_SUCCESS)
        goto close;

    /* work on reply */
    TEE_MemFill(cmd_buffer, 0, sizeof(cmd_buffer));
    res = wait_for_response(&ssl_ctx, (unsigned char*) cmd_buffer, sizeof(cmd_buffer));
    close_connection(tcp_ctx, &ssl_ctx);
    if (res != TEE_SUCCESS)
        goto clean;

    if (count_params(cmd_buffer, sizeof(cmd_buffer), 0) < 2) {
        res = TEE_ERROR_BAD_FORMAT;
        goto clean;
    }

    char param_buffer[512];
    offset = 0;
    if (get_next_parameter(cmd_buffer, sizeof(cmd_buffer), (uint16_t*) &offset, param_buffer, sizeof(param_buffer), NULL) != 0) {
        res = TEE_ERROR_BAD_FORMAT;
        goto clean;
    }

    if (param_buffer[0] != 'S') {
        res = TEE_ERROR_EXTERNAL_CANCEL;
        goto clean;
    }

    uint16_t output_buffer_offset;
    output_buffer_offset = 0;
    if (get_next_parameter(cmd_buffer, sizeof(cmd_buffer), (uint16_t*) &offset, param_buffer, sizeof(param_buffer), &output_buffer_offset) != 0) {
        res = TEE_ERROR_BAD_FORMAT;
        goto clean;
    }

    DMSG("signature size: %u", output_buffer_offset);

    ret = mbedtls_base64_decode((unsigned char*) signature_buffer, signature_buffer_size, &actually_written, (const unsigned char*) param_buffer, output_buffer_offset);
    if (ret != 0) {
        res = TEE_ERROR_BAD_FORMAT;
    }

    *signature_size = actually_written;

    goto clean;
close:
    close_connection(tcp_ctx, &ssl_ctx);

clean:
    clean_context(&ssl_conf, &ca_cert, &client_cert, &client_key, &ssl_ctx);

    return res;
}


TEE_Result get_nonce(char* buffer, size_t buffer_size) {
    if (buffer_size != 16)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_GenerateRandom(buffer, buffer_size);

    return TEE_SUCCESS;
}



/* ***************** */
/* COMMAND FUNCTIONS */
/* ***************** */


TEE_Result command_get_nonce(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    char nonce_buffer[16];

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types || params[0].memref.size != 16)
        return TEE_ERROR_BAD_PARAMETERS;

    res = get_nonce(nonce_buffer, sizeof(nonce_buffer));

    TEE_MemMove(params[0].memref.buffer, nonce_buffer, sizeof(nonce_buffer));

    return res;
}


TEE_Result command_enroll(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    res = enroll_certificate();
    if (res != TEE_SUCCESS)
        return res;

    res = enroll_csi_data();
    if (res != TEE_SUCCESS)
        delete_saved_certificate();

    return res;
}


TEE_Result command_prove(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types || params[0].memref.size != 16 | params[1].memref.size != 512)
        return TEE_ERROR_BAD_PARAMETERS;

    char nonce[16];
    char signature[512];
    size_t signature_size;

    TEE_MemMove(nonce, params[0].memref.buffer, 16);
    TEE_MemFill(signature, 0, sizeof(signature));

    res = create_prove(
        nonce, sizeof(nonce),
        signature, sizeof(signature),
        &signature_size
    );

    TEE_MemMove(params[1].memref.buffer, signature, sizeof(signature));
    params[2].value.a = signature_size;

    return res;
}


TEE_Result command_verify(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types || params[0].memref.size < 16 || params[1].memref.size > 512)
        return TEE_ERROR_BAD_PARAMETERS;

    char nonce[16];
    TEE_MemMove(nonce, params[0].memref.buffer, 16);

    char signature[512];
    TEE_MemMove(signature, params[1].memref.buffer, params[1].memref.size);

    return verify_signature(
        (const char*) nonce, sizeof(nonce),
        (const char*) signature, params[1].memref.size
    );
}


/* ********************** */
/* MANDATORY TA FUNCTIONS */
/* ********************** */


TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4] __maybe_unused, void** sess_ctx __maybe_unused) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void* sess_ctx __maybe_unused) {
}

TEE_Result TA_InvokeCommandEntryPoint(void* sess_ctx __maybe_unused, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
    switch (cmd_id)  {
        case TA_CONTEXT_BASED_AUTHENTICATION_CMD_GET_NONCE:
            return command_get_nonce(param_types, params);
        case TA_CONTEXT_BASED_AUTHENTICATION_CMD_ENROLL:
            return command_enroll(param_types, params);
        case TA_CONTEXT_BASED_AUTHENTICATION_CMD_PROVE:
            return command_prove(param_types, params);
        case TA_CONTEXT_BASED_AUTHENTICATION_CMD_VERIFY:
            return command_verify(param_types, params);
        default:
            return TEE_ERROR_NOT_SUPPORTED;
    };
}
