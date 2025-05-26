#ifndef TA_CONTEXT_BASED_AUTHENTICATION_COMMAND_PARSER_H
#define TA_CONTEXT_BASED_AUTHENTICATION_COMMAND_PARSER_H


#include <string.h>
#include <stdint.h>


uint16_t get_next_parameter(
    const char* input,
    uint16_t input_length,
    uint16_t* input_offset,

    char* output_buffer,
    uint16_t output_buffer_length,
    uint16_t* output_buffer_offset
);

uint16_t get_total_command_length(
    const char* input,
    uint16_t input_length,
    uint16_t offset
);

uint8_t count_params(
    const char* input,
    uint16_t input_length,
    uint16_t offset
);

uint16_t get_total_param_length(
    const char* input,
    uint16_t input_length,
    uint16_t offset
);

void join_parameters(
    const char* input,
    uint16_t input_length,
    uint16_t input_offset,

    char* output_buffer,
    uint16_t output_buffer_length
);

uint8_t has_complete_command(
    const char* input,
    uint16_t
);


#endif
