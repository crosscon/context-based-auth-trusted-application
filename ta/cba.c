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


#define TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME         "mac_filter"
#define TA_CONTEXT_BASED_AUTHENTICATION_BANDWIDTH               20
#define TA_CONTEXT_BASED_AUTHENTICATION_WIFI_CHANNEL            36
#define TA_CONTEXT_BASED_AUTHENTICATION_RECORDING_TIMEOUT       900
#define TA_CONTEXT_BASED_AUTHENTICATION_SAMPLES_PER_DEVICE      128



TEE_Result enroll_csi_data() {
    TEE_Result res;

    uint8_t available = false;
    uint8_t return_reason;
    uint32_t num_samples_collected;
    char cmd_buffer[512];
    uint8_t csi_buffer[265];
    mbedtls_ssl_context ssl_ctx;

    str_cat(cmd_buffer, "ENROLL_CSI\n", 11);

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

    res = open_connection(&ssl_ctx, true);
    if (res != TEE_SUCCESS)
        goto clean;

    res = send_command_data(&ssl_ctx, (const unsigned char*) cmd_buffer, strlen(cmd_buffer));
    if (res != TEE_SUCCESS)
        goto close;

    uint32_t offset;
    uint32_t actually_read;
    size_t actually_written;
    int ret;
    for (uint32_t i = 0; i < num_samples_collected; i++) {
        res = read_data(csi_buffer, sizeof(csi_buffer), offset, &actually_read);
        if (res != TEE_SUCCESS)
            return res;
        offset += actually_read;

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
            (const unsigned char*) cmd_buffer, sizeof(cmd_buffer)
        );
        if (res != TEE_SUCCESS)
            goto close;
    }

    cmd_buffer[0] = '\n';
    cmd_buffer[1] = '\0';
    res = send_command_data(&ssl_ctx, (unsigned char*) cmd_buffer, 2);
    if (res != TEE_SUCCESS)
        goto close;

    res = wait_for_response(&ssl_ctx, (unsigned char*) cmd_buffer, sizeof(cmd_buffer));
    close_connection(&ssl_ctx);
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

    if (param_buffer[0] != 'O') {
        res = TEE_ERROR_EXTERNAL_CANCEL;
        goto clean;
    }

    if (get_next_parameter(cmd_buffer, sizeof(cmd_buffer), (uint16_t*) &offset, param_buffer, sizeof(param_buffer), NULL) != 0) {
        res = TEE_ERROR_BAD_FORMAT;
        goto clean;
    }

    ret = mbedtls_base64_decode((unsigned char*) cmd_buffer, sizeof(cmd_buffer), &actually_written, (const unsigned char*) param_buffer, sizeof(param_buffer));
    if (ret != 0) {
        res = TEE_ERROR_BAD_FORMAT;
        goto clean;
    }

    res = write_object(TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME, strlen(TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME), cmd_buffer, actually_written);
    if (res != TEE_SUCCESS) {
        goto clean;
    }

close:
    close_connection(&ssl_ctx);

clean:
    clean_context(&ssl_ctx);

    return res;
}


TEE_Result create_prove(char* nonce, size_t nonce_size, char* signature_buffer, size_t signature_buffer_size) {
    TEE_Result res;

    uint8_t available = false;
    uint8_t return_reason;
    uint32_t num_samples_collected;
    char cmd_buffer[512];
    uint8_t csi_buffer[265];
    mbedtls_ssl_context ssl_ctx;

    uint32_t offset;
    uint32_t actually_read;
    size_t actually_written;
    int ret;

    ret = mbedtls_base64_encode((unsigned char*) csi_buffer, sizeof(csi_buffer), &actually_written, (const unsigned char*) nonce, sizeof(nonce));
    if (ret != 0)
        return TEE_ERROR_BAD_STATE;

    str_cat(cmd_buffer, "PROVE\n", 11);
    str_cat(cmd_buffer, (const char*) csi_buffer, actually_written);
    str_cat(cmd_buffer, "\n", 1);

    res = read_object_if_exists_with_length(
        TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME,
        strlen(TA_CONTEXT_BASED_AUTHENTICATION_MAC_FILTER_NAME),
        (char*) csi_buffer, sizeof(csi_buffer),
        (size_t*) &actually_read
    );
    if (res != TEE_SUCCESS)
        return res;
    res = set_mac_filter(csi_buffer, actually_read / 6);
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

    res = open_connection(&ssl_ctx, true);
    if (res != TEE_SUCCESS)
        goto clean;

    res = send_command_data(&ssl_ctx, (const unsigned char*) cmd_buffer, strlen(cmd_buffer));
    if (res != TEE_SUCCESS)
        goto close;

    for (uint32_t i = 0; i < num_samples_collected; i++) {
        res = read_data(csi_buffer, sizeof(csi_buffer), offset, &actually_read);
        if (res != TEE_SUCCESS)
            return res;
        offset += actually_read;

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
            (const unsigned char*) cmd_buffer, sizeof(cmd_buffer)
        );
        if (res != TEE_SUCCESS)
            goto close;
    }

    cmd_buffer[0] = '\n';
    cmd_buffer[1] = '\0';
    res = send_command_data(&ssl_ctx, (unsigned char*) cmd_buffer, 2);
    if (res != TEE_SUCCESS)
        goto close;

    res = wait_for_response(&ssl_ctx, (unsigned char*) cmd_buffer, sizeof(cmd_buffer));
    close_connection(&ssl_ctx);
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

    if (param_buffer[0] != 'O') {
        res = TEE_ERROR_EXTERNAL_CANCEL;
        goto clean;
    }

    if (get_next_parameter(cmd_buffer, sizeof(cmd_buffer), (uint16_t*) &offset, param_buffer, sizeof(param_buffer), NULL) != 0) {
        res = TEE_ERROR_BAD_FORMAT;
        goto clean;
    }

    TEE_MemMove(signature_buffer, param_buffer, strlen(param_buffer) + 1);
close:
    close_connection(&ssl_ctx);

clean:
    clean_context(&ssl_ctx);

    return res;
}


TEE_Result get_nonce(char* buffer, size_t buffer_size) {
    if (buffer_size < 16)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_GenerateRandom(buffer, buffer_size);

    return TEE_SUCCESS;
}



/* ***************** */
/* COMMAND FUNCTIONS */
/* ***************** */


TEE_Result command_get_nonce(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    return get_nonce(params[0].memref.buffer, params[0].memref.size);
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

    return res;
}


TEE_Result command_prove(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    return create_prove(
        params[0].memref.buffer, params[0].memref.size,
        params[1].memref.buffer, params[1].memref.size
    );
}


TEE_Result command_verify(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    return verify_signature(
        (const char*) params[0].memref.buffer, params[0].memref.size,
        (const char*) params[1].memref.buffer, params[1].memref.size
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
