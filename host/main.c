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

    char nonce_buffer[32];
    memset(nonce_buffer, 3, sizeof(nonce_buffer));
    char signature_buffer[32];

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
        printf("Error: No arg given. Either 'start' or 'read' required.");
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
        printf("Invalid parameter(s).\n");
    }

    return 0;
}
