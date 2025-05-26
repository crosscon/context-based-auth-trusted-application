#include "command_parser.h"


uint16_t get_next_parameter(const char* input, uint16_t input_length, uint16_t* input_offset, char* output_buffer, uint16_t output_buffer_length, uint16_t* output_buffer_offset) {
    uint16_t i = 0;
    uint16_t op_off;

    if (output_buffer_offset == NULL) {
        op_off = 0;
    } else {
        op_off = *(output_buffer_offset);
    }

    while (i < (input_length - (*input_offset)) && i < (output_buffer_length - op_off) && input[*input_offset + i] != '\n' && input[*input_offset + i] != '\0') {
        output_buffer[op_off + i] = input[*input_offset + i];
        i++;
    }

    *input_offset = (*input_offset) + i + 1;

    if (output_buffer_offset != NULL) {
        (*output_buffer_offset) = op_off + i;
    }

    return 0;
}


uint16_t get_total_command_length(const char* input, uint16_t input_length, uint16_t offset) {
    for (uint16_t i = offset + 1; i < input_length; i++) {
        if (input[i - 1] == '\n' && input[i] == '\n') {
            return i - offset;
        }
    }

    return -1;
}


uint8_t count_params(const char* input, uint16_t input_length, uint16_t offset) {
    uint8_t counter = 0;

    for (uint32_t i = offset + 1; i < input_length; i++) {
        if (input[i - 1] == '\n' && input[i] == '\n') {
            return counter;
        } else if (input[i] == '\n') {
            counter++;
        }
    }

    return counter;
}


uint16_t get_total_param_length(const char* input, uint16_t input_length, uint16_t offset) {
    return get_total_command_length(input, input_length, offset) - count_params(input, input_length, offset);
}


void join_parameters(const char* input, uint16_t input_length, uint16_t input_offset, char* output_buffer, uint16_t output_buffer_length) {
    uint8_t num_params = count_params(input, input_length, input_offset);
    uint16_t output_buffer_offset = 0;

    for (uint8_t i = 0; i < num_params; i++) {
        get_next_parameter(input, input_length, &input_offset, output_buffer, output_buffer_length, &output_buffer_offset);
        output_buffer[output_buffer_offset++] = '\n';
    }
    output_buffer[output_buffer_offset - 1] = '\0';
}


uint8_t has_complete_command(const char* input, uint16_t input_length) {
    for (uint16_t i = 1; i < input_length; i++) {
        if (input[i - 1] == '\n' && input[i] == '\n') {
            return 1;
        }
    }

    return 0;
}

