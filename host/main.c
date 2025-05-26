#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <context_based_authentication.h>


void test_memread() {
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
        TEEC_VALUE_OUTPUT,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE
    );

    res = TEEC_InvokeCommand(&sess, TA_CONTEXT_BASED_AUTHENTICATION_CMD_TEST_MEM_READ, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return;
    }

    printf("TA result: %u (%u)\n", op.params[0].value.a, op.params[0].value.b);

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
}


void test_start_recording() {
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

    res = TEEC_InvokeCommand(&sess, TA_CONTEXT_BASED_AUTHENTICATION_CMD_TEST_START_REC, &op, &err_origin);
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

    if (strcmp(arg, "start") == 0) {
        test_start_recording();
    } else if (strcmp(arg, "read") == 0) {
        test_memread();
    } else {
        printf("Invalid parameter(s).\n");
    }

    return 0;
}
