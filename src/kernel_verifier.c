#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <string.h>

#include <dirent.h>
#include <sys/resource.h>

#include "kernel_verifier.h"

#define ITERS 512 
#define BUFSIZE 512
#define TRACE_FILE "/sys/kernel/debug/tracing/trace"

int regs[] = {
    BPF_REG_0,
    BPF_REG_1,
    BPF_REG_2,
    BPF_REG_3,
    BPF_REG_4,
    BPF_REG_5,
    BPF_REG_6,
    BPF_REG_7,
    BPF_REG_8,
    BPF_REG_9,
};

char *read_line(int fd)
{
    char read_buffer[BUFSIZE];
    memset(read_buffer, 0, BUFSIZE);

    char *line = NULL;
    
    int bytes_read = 0;
    int offset = lseek(fd, 0, SEEK_CUR);
    int line_size = 0;

    int nl = 0;

    while (nl == 0 && (bytes_read = read(fd, read_buffer, BUFSIZE-1)) > 0)
    {
        for (int charidx = 0; charidx < bytes_read; charidx++)
        {
            if (read_buffer[charidx] == '\n')
            {
                lseek(fd, offset + charidx + 1, SEEK_SET);
                bytes_read = charidx + 1;
                nl = 1;
                break;
            }
        }

        line = realloc(line, sizeof(char) * (line_size + bytes_read));
        memmove(line + line_size, read_buffer, bytes_read);
        offset += bytes_read;
        line_size += bytes_read;

        memset(read_buffer, 0, BUFSIZE);
    }

    if (line_size == 0) return NULL;

    line[line_size-1] = 0;
    return line;
}

bpf_prog gen_prog(abstract_register_state *state, struct bpf_insn test_insn)
{
    bpf_prog prog;
    int bpf_insn_size = 8;
    int num_insns = 0;

    prog.insns = malloc(1);

    for (int i = 0; i < 4; i++) {
        abstract_register_state curr_reg = state[i];
        if (curr_reg.mask == FULLY_UNKNOWN)
        {
            num_insns += 2;
            prog.insns = realloc(prog.insns, bpf_insn_size * num_insns);
            prog.insns[num_insns-2] = BPF_MOV64_IMM(regs[i], 0);
            prog.insns[num_insns-1] = BPF_ALU64_IMM(BPF_NEG, regs[i], 0);
        }
        else
        {
            num_insns += 2;
            prog.insns = realloc(prog.insns, bpf_insn_size * num_insns);
            struct bpf_insn ld_imm64_insn[2] = {BPF_LD_IMM64(regs[i], curr_reg.value)};
            prog.insns[num_insns-2] = ld_imm64_insn[0];
            prog.insns[num_insns-1] = ld_imm64_insn[1];
        }
    }

    num_insns += 3;
    prog.insns = realloc(prog.insns, bpf_insn_size * num_insns);
    prog.insns[num_insns-3] = test_insn;
    prog.insns[num_insns-2] = BPF_MOV64_IMM(BPF_REG_0, 0);
    prog.insns[num_insns-1] = BPF_EXIT_INSN();

    prog.size = num_insns * bpf_insn_size;

    return prog;
}

void assign_reg(abstract_register_state *reg, char *val)
{
    if (strcmp(val, "unknown") == 0)
    {
        reg->mask = FULLY_UNKNOWN;
        reg->value = 0;
    }
    else
    {
        // TODO error checking on stroll
        reg->mask = SINGLETON;
        reg->value = strtoull(val, NULL, 10);
    }
}

void assign_test_insn(struct bpf_insn *insn, char *operation)
{
    if (strcmp(operation, "ADD") == 0)
    {
        *insn = BPF_ALU64_REG(0x00, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "SUB") == 0)
    {
        *insn = BPF_ALU64_REG(0x10, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "MUL") == 0)
    {
        *insn = BPF_ALU64_REG(0x20, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "DIV") == 0)
    {
        *insn = BPF_ALU64_REG(0x30, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "OR") == 0)
    {
        *insn = BPF_ALU64_REG(0x40, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "AND") == 0)
    {
        *insn = BPF_ALU64_REG(0x50, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "LSH") == 0)
    {
        *insn = BPF_ALU64_REG(0x60, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "RSH") == 0)
    {
        *insn = BPF_ALU64_REG(0x70, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "NEG") == 0)
    {
        *insn = BPF_ALU64_REG(0x80, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "MOD") == 0)
    {
        *insn = BPF_ALU64_REG(0x90, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "XOR") == 0)
    {
        *insn = BPF_ALU64_REG(0xa0, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "MOV") == 0)
    {
        *insn = BPF_ALU64_REG(0xb0, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "ARSH") == 0)
    {
        *insn = BPF_ALU64_REG(0xc0, BPF_REG_1, BPF_REG_2);
    } 
    else if (strcmp(operation, "END") == 0)
    {
        *insn = BPF_ALU64_REG(0xd0, BPF_REG_1, BPF_REG_2);
    }
    else
    {
        memset(insn, 0, sizeof(struct bpf_insn));
    }
}


int load_prog(bpf_prog prog, int print_log)
{
    int prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog.insns, prog.size,
            "GPL", 0);

    if (print_log)
    {
        printf("VERIFIER LOG:\n%s", bpf_log_buf);
    }

    if (prog_fd < 0)
    {
        return prog_fd;
    }

    close(prog_fd);

    return 0;
}

char ***get_insns(int input_fd)
{
    char **insn_lines = NULL;
    int num_insns = 0;

    char *new_line = NULL;

    while (1)
    {
        new_line = read_line(input_fd);
        if (new_line == NULL) break;
        
        num_insns += 1;
        insn_lines = realloc(insn_lines, num_insns * sizeof(char *));
        insn_lines[num_insns-1] = new_line;
    }

    char ***final_insn_list = malloc((num_insns+1) * sizeof(char **));
    for (int i = 0; i < num_insns; i++)
    {
        // break up insn into peices by strtok_r
        char *save_ptr;
        char *insn_fragment = strtok_r(insn_lines[i], " ", &save_ptr);
        char **insn_list_entry = NULL;
        int entry_len = 0;

        while (insn_fragment != NULL)
        {
            int insn_fragment_len = strlen(insn_fragment) + 1;
            entry_len++;
            insn_list_entry = realloc(insn_list_entry, entry_len * sizeof(char *));
            insn_list_entry[entry_len-1] = malloc(insn_fragment_len);
            strncpy(insn_list_entry[entry_len-1], insn_fragment, insn_fragment_len); 

            insn_fragment = strtok_r(NULL, " ", &save_ptr);
        }

        insn_list_entry = realloc(insn_list_entry, entry_len + 1);
        insn_list_entry[entry_len] = 0; // null terminated

        // TODO validate insn i.e. making sure arguments fit op and op is valid

        final_insn_list[i] = insn_list_entry;
    }

    final_insn_list[num_insns] = 0; // null termiante

    // TODO do deallocations

    return final_insn_list; 
}

void print_outputs(int trace_fd, int num_outputs, int min_prog_id)
{
    char **outputs = NULL;
    int outputs_consumed = 0;

    char *new_output = NULL;
    // 12 lines of garbage at beginning of trace
    while (outputs_consumed < 12 + num_outputs) 
    {
        if (outputs_consumed < 12)
        {
            read_line(trace_fd);
            outputs_consumed += 1;
            continue;
        }

        new_output = read_line(trace_fd);
        
        outputs_consumed += 1;
        outputs = realloc(outputs, (outputs_consumed-12) * sizeof(char *));
        outputs[outputs_consumed-13] = new_output;
    }

    char ***reg_states = NULL;
    int order[num_outputs];
    
    for (int i = 0; i < num_outputs; i++)
    {
        // Each one of these will be a list of the entire output broken up by spaces
        char *save_ptr;
        char *reg_state_frag = strtok_r(outputs[i], " ", &save_ptr);
        char **reg_state_frags = NULL;
        int reg_state_len = 0;
        
        int skip_garbage = 0;
        while (reg_state_frag != NULL)
        {
            // 5 garbage tokens at beginning of each trace
            if (skip_garbage < 5)
            {
                reg_state_frag = strtok_r(NULL, " ", &save_ptr);
                skip_garbage++;
                continue;
            }

            int reg_state_frag_len = strlen(reg_state_frag) + 1; // +1 for null term
            reg_state_len++;
            reg_state_frags = realloc(reg_state_frags, reg_state_len * sizeof(char *));
            reg_state_frags[reg_state_len-1] = malloc(reg_state_frag_len);
            strncpy(reg_state_frags[reg_state_len-1], reg_state_frag, reg_state_frag_len); 

            reg_state_frag = strtok_r(NULL, " ", &save_ptr);
        }

        reg_states = realloc(reg_states, sizeof(char **) * (i+1));
        reg_states[i] = reg_state_frags;

        int prog_id = atoi(reg_states[i][30]);
        
        order[prog_id - min_prog_id] = i;
    }

    for (int i = 0; i < num_outputs; i++)
    {
        char **output_frags = reg_states[order[i]];
        for (int j = 10; j < 20; j++)
        {
            printf("%s ", output_frags[j]);
        }
        printf("\n");
    }
}

/* Structure:
 * 1. Get all the instructions from input file. 
 * 2. For each input, get output and print to real_verifier_output.
 * 3. After every X number of inputs, clear the trace file.
 *
 * TODO:
 * 1. Read all instructions into array of array of characters
 * 2. Think about how to make this threaded while retaining order of output.
 * 3. Update trace output to have easier to deal with structure.
 *    - Flatten it and remove labels so we can just use strtok_r easily.
 *    - give each input some unique numbering -- might help with threading as well
 *    - put that numbering into some fixed register
 *    - print that registers value in trace to match it when reading trace
 */

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: ./verifier_test <input_path>\n");
        return EXIT_FAILURE;
    }

    /* process command line arguments */

    int input_fd = open(argv[1], O_RDONLY);
    if (input_fd < 0)
    {
        fprintf(stderr, "Failed to open provided path\n");
        return 1;
    }

    char ***insn_strs = get_insns(input_fd); 
    close(input_fd);
    int iters = ITERS;
    int k = 0;
    
    /* run some number of test programs */
    fclose(fopen(TRACE_FILE, "w"));
    while (insn_strs[k] != 0)
    {
        int i;
        for (i = k; insn_strs[i] != 0 && i < k + iters; i++)
        {
            abstract_register_state reg_1;
            abstract_register_state reg_2;

            assign_reg(&reg_1, insn_strs[i][1]);
            assign_reg(&reg_2, insn_strs[i][2]);

            abstract_register_state state[] = {
                {.mask = SINGLETON, .value = 0},
                reg_1,
                reg_2,
                {.mask = SINGLETON, .value = i}           
            };

            struct bpf_insn test_insn;
            assign_test_insn(&test_insn, insn_strs[i][0]);

            bpf_prog prog = gen_prog(state, test_insn);
            if (load_prog(prog, 0) < 0)
            {
                printf("PROGRAM FAILED VERIFICATION: %s\n", strerror(errno));
                return EXIT_FAILURE;
            }
        }    

        iters = i - k;

        /* READ TRACE */

        int trace_fd = open(TRACE_FILE, O_RDONLY);
        if (trace_fd < 0)
        {
            printf("Not able to open trace buffer.\n");
            return EXIT_FAILURE;
        }
        
        print_outputs(trace_fd, iters, k);
        close(trace_fd); 
        fclose(fopen(TRACE_FILE, "w"));

        k += iters;      
    }

    return 0;
}
