#ifndef TA_CONTEXT_BASED_AUTHENTICATION_STORAGE_HANDLING_H
#define TA_CONTEXT_BASED_AUTHENTICATION_STORAGE_HANDLING_H


#include <stdint.h>
#include <tee_internal_api.h>


#define STORAGE_ID_PRIVATE_KEY "client_key"
#define STORAGE_ID_CLIENT_CERT "client_cert"


TEE_Result write_object(
    const char* object_id,
    size_t object_id_length,
    const char* data,
    size_t data_size
);


TEE_Result read_object_if_exists_with_length(
    const char* object_id,
    size_t object_id_length,
    char* buffer,
    size_t buffer_size,
    size_t* read
);


TEE_Result read_object_if_exists(
    const char* object_id,
    size_t object_id_length,
    char* buffer,
    size_t buffer_size
);


TEE_Result get_id(
    char buffer[4]
);


#endif
