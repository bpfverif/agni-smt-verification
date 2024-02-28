#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

uint64_t rand_uint64() 
{
    uint64_t val;
    size_t count;
    FILE *rand_source = fopen("/dev/urandom", "r");

    do 
    {
        count = fread(&val, sizeof(val), 1, rand_source);
    } 
    while (count != 1);

    return val;
}

#define INVALID_ARGS "Unexpected Arguments\nUsage: rand_input <insns> <input size> <file_path>\n"

/* This program will give a set of random inputs to test on.
 * We will select from the pool of inputs with replacement.
 * We can give a probability for unknowns that is adjustable.
 * We should structure the inputs as a set of instructions.
 * example: ADD 1 1, MUL unknown 1000
 */
int main(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr,  INVALID_ARGS);
        return 1;
    }
    
    char *save_ptr; 
    char *insns_str = argv[1];
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

    for (int i = 0; i < num_insns; i++)
    {
        printf("%s\n", insns[i]);
    }
}
