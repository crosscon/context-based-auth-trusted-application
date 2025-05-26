#ifndef TA_CONTEXT_BASED_AUTHENTICATION_CSI_PTA_WRAPPER_H
#define TA_CONTEXT_BASED_AUTHENTICATION_CSI_PTA_WRAPPER_H

#include <tee_internal_api.h>
#include <pta_csi.h>


TEE_Result invoke_pta_command(
    uint32_t cmd_id,
    uint32_t pta_param_types,
    TEE_Param pta_params[4]
);


TEE_Result check_if_response_available(
    uint8_t* available,
    uint8_t* return_reason,
    uint32_t* num_samples_collected
);


TEE_Result read_data(
    uint8_t* buffer,
    uint32_t buffer_size,
    uint32_t read_offset,
    uint32_t* actually_read
);


TEE_Result set_mac_filter(
    uint8_t* mac_addrs,
    uint8_t num_macs
);


TEE_Result disable_mac_filter();


TEE_Result set_recording_parameters_and_start(
    uint8_t wifi_channel,
    uint8_t wifi_channel_bandwidth,
    uint16_t recording_timeout,
    uint8_t num_samples_per_device
);


#endif /* TA_CONTEXT_BASED_AUTHENTICATION_CSI_PTA_WRAPPER_H */
