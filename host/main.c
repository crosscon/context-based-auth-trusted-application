#include <math.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <context_based_authentication.h>


void test_nonce() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CONTEXT_BASED_AUTHENTICATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x", res);
        return;
    }

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
        printf("TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
        return;
    }

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE
    );

    char buffer[16];
    op.params[0].tmpref.buffer = buffer;
    op.params[0].tmpref.size = sizeof(buffer);

    res = TEEC_InvokeCommand(&sess, TA_CONTEXT_BASED_AUTHENTICATION_CMD_GET_NONCE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return;
    }

    printf("TA result: %x %x ... %x\n", buffer[0], buffer[1], buffer[15]);

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
}


void test_enroll() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CONTEXT_BASED_AUTHENTICATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x", res);
        return;
    }

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
        printf("TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
        return;
    }

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE
    );

    res = TEEC_InvokeCommand(&sess, TA_CONTEXT_BASED_AUTHENTICATION_CMD_ENROLL, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return;
    }

    printf("TA result: Ok.\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
}



void test_prove() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CONTEXT_BASED_AUTHENTICATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x", res);
        return;
    }

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
        printf("TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
        return;
    }

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE,
        TEEC_NONE
    );

    char nonce_buffer[16];
    memset(nonce_buffer, 0, sizeof(nonce_buffer));
    op.params[0].tmpref.buffer = nonce_buffer;
    op.params[0].tmpref.size = sizeof(nonce_buffer);

    char signature_buffer[512];;
    op.params[1].tmpref.buffer = signature_buffer;
    op.params[1].tmpref.size = sizeof(signature_buffer);

    res = TEEC_InvokeCommand(&sess, TA_CONTEXT_BASED_AUTHENTICATION_CMD_PROVE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return;
    }

    printf("TA result: Ok\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

}


void test_verify() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_CONTEXT_BASED_AUTHENTICATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x", res);
        return;
    }

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
        printf("TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
        return;
    }

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_NONE,
        TEEC_NONE
    );

    char nonce_buffer[16];
    memset(nonce_buffer, 0, sizeof(nonce_buffer));
    char signature_buffer[71] = { 48, 69, 2, 33, 0, 238, 79, 112, 36, 34, 39, 135, 111, 5, 163, 245, 18, 25, 141, 101, 208, 126, 207, 17, 186, 27, 110, 168, 119, 161, 30, 50, 57, 93, 94, 164, 210, 2, 32, 21, 27, 55, 25, 232, 5, 147, 139, 92, 113, 13, 15, 178, 212, 240, 147, 20, 202, 89, 124, 194, 185, 234, 228, 2, 3, 98, 70, 57, 122, 147, 21 };

    op.params[0].tmpref.buffer = nonce_buffer;
    op.params[0].tmpref.size = sizeof(nonce_buffer);
    op.params[1].tmpref.buffer = signature_buffer;
    op.params[1].tmpref.size = sizeof(signature_buffer);

    res = TEEC_InvokeCommand(&sess, TA_CONTEXT_BASED_AUTHENTICATION_CMD_VERIFY, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return;
    }

    printf("TA result: Ok\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

}


int main(int argc, char** argv) {
    if (argc <= 1) {
        printf("Possible parameters are:");
        printf(" - nonce: generate a nonce within the TEE (output truncated)");
        printf(" - enroll: enroll first the certificate, then the initial CSI data at the remote");
        printf(" - prove: create a prove based on the current wireless environment using a hard-coded nonce");
        printf(" - verify: verify a (hardcoded) signature against the remote's public key and the actual nonce used");
        return 1;
    }

    char* arg = argv[1];

    if (strcmp(arg, "nonce") == 0) {
        test_nonce();
    } else if (strcmp(arg, "enroll") == 0) {
        test_enroll();
    } else if (strcmp(arg, "prove") == 0) {
        test_prove();
    } else if (strcmp(arg, "verify") == 0) {
        test_verify();
    } else {
        printf("Invalid parameter(s). Run without any parameters to see possible values.\n");
    }

    return 0;
}
