#include <tee_internal_api.h>
#include <string.h>

#include "storage_handling.h"



TEE_Result write_object(const char* object_id, size_t object_id_length, const char* data, size_t data_size) {
    TEE_ObjectHandle handle;
    TEE_Result res;

    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,
        object_id, object_id_length,
        TEE_DATA_FLAG_ACCESS_WRITE |
        TEE_DATA_FLAG_ACCESS_WRITE_META |
        TEE_DATA_FLAG_ACCESS_READ |
        TEE_DATA_FLAG_OVERWRITE,
        TEE_HANDLE_NULL,
        NULL, 0,
        &handle
    );

    if (res == TEE_SUCCESS)
        res = TEE_WriteObjectData(handle, data, data_size);

    TEE_CloseObject(handle);

    return res;
}


TEE_Result read_object_if_exists_with_length(const char* object_id, size_t object_id_length, char* buffer, size_t buffer_size, size_t* read) {
    TEE_ObjectHandle handle;
    TEE_ObjectInfo info;
    TEE_Result res;

    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        object_id, object_id_length,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
        &handle
    );

    if (res == TEE_SUCCESS) {
        res = TEE_GetObjectInfo1(handle, &info);

        if (res == TEE_SUCCESS) {
            if (info.dataSize <= buffer_size) {
                res = TEE_ReadObjectData(handle, buffer, info.dataSize, read);
            } else {
                res = TEE_ERROR_SHORT_BUFFER;
            }
        }
    }

    TEE_CloseObject(handle);

    return res;
}


TEE_Result read_object_if_exists(const char* object_id, size_t object_id_length, char* buffer, size_t buffer_size) {
    size_t read;
    return read_object_if_exists_with_length(
        object_id, object_id_length, buffer, buffer_size, &read
    );
}


TEE_Result get_id(char buffer[4]) {
    const char* id = "device_id";
    size_t id_len = strlen(id);

    if (read_object_if_exists(id, id_len, buffer, 4) == TEE_SUCCESS)
        return TEE_SUCCESS;

    TEE_GenerateRandom(buffer, 4);

    return write_object(id, id_len, buffer, 4);
}
