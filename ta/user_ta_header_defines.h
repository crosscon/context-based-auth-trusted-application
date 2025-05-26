#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <context_based_authentication.h>

#define TA_UUID TA_CONTEXT_BASED_AUTHENTICATION_UUID

#define TA_FLAGS TA_FLAG_EXEC_DDR

#define TA_STACK_SIZE (1 * 1024 * 1024)
#define TA_DATA_SIZE (64 * 1024)

#define TA_VERSION "0.1"

#define TA_DESCRIPTION "A TA for a novel context-based authentication service"

#endif /* USER_TA_HEADER_DEFINES_H */
