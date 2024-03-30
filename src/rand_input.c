#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define INVALID_ARGS "Unexpected Arguments\nUsage: rand_input <insns> <input size> <file_path>\n"

FILE *rand_source;

// str must be null terminated
int safe_write(int fd, char *str)
{
    int bytes = 0;

    while ((bytes = write(fd, str, strlen(str))) > 0)
    {
        str += bytes;
    }

    if (str[0] != '\0')
    {
        return 1;
    }

    return 0;
}

uint64_t rand_uint64() 
{
    uint64_t val;
    size_t count;

    do 
    {
        count = fread(&val, sizeof(val), 1, rand_source);
    } 
    while (count != 1);
    
    return val;
}

char *uint64_to_string(uint64_t val)
{
    uint64_t x = val;
    int len = 0;
    for (;x > 0; x /= 10) len++;

    char *val_str = malloc(len+1);
    
    snprintf(val_str, len+1, "%lu", val);

    return val_str;
}

/* This program will give a set of random inputs to test on.
 * We will select from the pool of inputs with replacement.
 * We can give a probability for unknowns that is adjustable.
 * We should structure the inputs as a set of instructions.
 * example: ADD 1 1, MUL unknown 1000
 */
int main(int argc, char **argv)
{
    rand_source = fopen("/dev/urandom", "r");

    if (argc != 4)
    {
        fprintf(stderr,  INVALID_ARGS);
        return 1;
    }

    char *insns_str = argv[1];
    char *inputs_path = argv[3];
    uint64_t input_size = strtoull(argv[2], NULL, 10);
    
    char *save_ptr; 
    char *insn = strtok_r(insns_str, ",", &save_ptr);

    char **insns = NULL;
    int num_insns = 0;

    while (insn != NULL)
    {
        int insn_str_len = strlen(insn) + 1;

        num_insns++;
        insns = realloc(insns, num_insns * sizeof(char *));
        insns[num_insns-1] = malloc(insn_str_len);
        strncpy(insns[num_insns-1], insn, insn_str_len);

        insn = strtok_r(NULL, ",", &save_ptr);
    }
    
    // TODO validate instructions
    
    int fd = open(inputs_path, O_CREAT | O_WRONLY | O_TRUNC,
            S_IRUSR | S_IWUSR);
 
    // Each line is a specification for a test program
    for (int i = 0; i < num_insns; i++)
    {
        for (int j = 0; j < input_size; j++)
        {
            // TODO add checking for instruction type to give correct input
            
            char *val_str_1 = uint64_to_string(rand_uint64());
            char *val_str_2 = uint64_to_string(rand_uint64());
            
            // TODO Not sure how unknowns should be distribued
            int r1 = rand() % 50;
            int r2 = rand() % 50;

            val_str_1 = r1 == 0 ? "unknown" : val_str_1;
            val_str_2 = r2 == 0 ? "unknown" : val_str_2;

            size_t input_len = 
                strlen(val_str_1) + strlen(val_str_2) + strlen(insns[i]) + 4;
            char *input = malloc(input_len);

            snprintf(input, input_len, "%s %s %s\n", insns[i], val_str_1, val_str_2);

            safe_write(fd, input);
            
            if (r1 != 0) free(val_str_1);
            if (r2 != 0)free(val_str_2);
            free(input);
        }
    }

    for (int i = 0; i < num_insns; i++)
    {
        free(insns[i]);
    }
    free(insns);

    fclose(rand_source);
}


