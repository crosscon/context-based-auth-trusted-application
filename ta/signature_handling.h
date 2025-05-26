#ifndef TA_CONTEXT_BASED_AUTHENTICATION_SIGNATURE_HANDLING_H
#define TA_CONTEXT_BASED_AUTHENTICATION_SIGNATURE_HANDLING_H


#include <tee_internal_api.h>


TEE_Result verify_signature(
    const char* nonce,
    size_t nonce_size,
    const char* signature,
    size_t signature_size
);


#endif /* TA_CONTEXT_BASED_AUTHENTICATION_SIGNATURE_HANDLING_H */
