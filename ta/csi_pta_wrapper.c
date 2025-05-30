#include <tee_internal_api.h>
#include <pta_csi.h>

#include "csi_pta_wrapper.h"


TEE_Result invoke_pta_command(uint32_t cmd_id, uint32_t pta_param_types, TEE_Param pta_params[4]) {
    TEE_UUID uuid = PTA_CSI_UUID;
    TEE_TASessionHandle sess;
    TEE_Result res;
    uint32_t ret_origin;

    res = TEE_OpenTASession(&uuid, 0, 0, NULL, &sess, &ret_origin);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_InvokeTACommand(
        sess, 0,
        cmd_id,
        pta_param_types, pta_params,
        &ret_origin
    );

    TEE_CloseTASession(sess);

    return res;
}


TEE_Result check_if_response_available(uint8_t* available, uint8_t* return_reason, uint32_t* num_samples_collected) {
    TEE_Result res;
    uint32_t pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE
    );

    TEE_Param params[4] = { 0 };

    res = invoke_pta_command(
        PTA_CSI_CMD_CHECK_IF_RESPONSE_AVAILABLE,
        pt, params
    );

    if (res != TEE_SUCCESS)
        return res;

    *available = params[0].value.a;
    *return_reason = params[1].value.a;
    *num_samples_collected = params[2].value.a;

    return res;
}


TEE_Result read_data(uint8_t* buffer, uint32_t buffer_size, uint32_t read_offset, uint32_t* actually_read) {
    TEE_Result res;
    uint32_t pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE
    );

    TEE_Param params[4] = { 0 };

    uint8_t* local_buffer = TEE_Malloc(buffer_size, TEE_MALLOC_FILL_ZERO);

    params[0].memref.buffer = local_buffer;
    params[0].memref.size = buffer_size;
    params[1].value.a = read_offset;

    res = invoke_pta_command(
        PTA_CSI_CMD_READ_DATA,
        pt, params
    );

    if (res != TEE_SUCCESS)
        goto clean;

    *actually_read = params[2].value.a;
    TEE_MemMove(buffer, local_buffer, *actually_read);

clean:
    TEE_Free(local_buffer);

    return res;
}


TEE_Result set_mac_filter(uint8_t* mac_addrs, uint8_t num_macs) {
    uint32_t pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    TEE_Param params[4] = { 0 };

    params[0].memref.buffer = mac_addrs;
    params[0].memref.size = num_macs * 6;

    return invoke_pta_command(
        PTA_CSI_CMD_SET_MAC_FILTER,
        pt, params
    );
}


TEE_Result disable_mac_filter() {
    uint32_t pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    TEE_Param params[4] = { 0 };

    return invoke_pta_command(
        PTA_CSI_CMD_DISABLE_MAC_FILTER,
        pt, params
    );
}


TEE_Result set_recording_parameters_and_start(uint8_t wifi_channel, uint8_t wifi_channel_bandwidth, uint16_t recording_timeout, uint8_t num_samples_per_device) {
    uint32_t pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT
    );

    TEE_Param params[4] = { 0 };

    params[0].value.a = wifi_channel;
    params[1].value.a = wifi_channel_bandwidth;
    params[2].value.a = recording_timeout;
    params[3].value.a = num_samples_per_device;

    return invoke_pta_command(
        PTA_CSI_CMD_SET_PARAMS_AND_START,
        pt, params
    );
}


TEE_Result zero_all(void) {
    uint32_t pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    TEE_Param params[4] = { 0 };

    return invoke_pta_command(
        PTA_CSI_CMD_ZERO_ALL,
        pt, params
    );
}
