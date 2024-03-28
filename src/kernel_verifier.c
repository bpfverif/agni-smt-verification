#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "libbpf.h"
#include "verifier_test.h"
#include "string.h"

#define BUFSIZE 40
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

    for (int i = 0; i < 3; i++) {
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
        reg->value = strtoll(val, NULL, 10);
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

void compute_lps_array(char* pat, int M, int* lps)
{
    int len = 0;

    lps[0] = 0; 

    int i = 1;
    while (i < M) 
    {
        if (pat[i] == pat[len]) 
        {
            len++;
            lps[i] = len;
            i++;
        }
        else 
        {
            if (len != 0) 
            {
                len = lps[len - 1];
            }
            else 
            {
                lps[i] = 0;
                i++;
            }
        }
    }
}


int kmp_search(char* pat, char* txt)
{
    int M = strlen(pat);
    int N = strlen(txt);

    int lps[M];

    int *results = NULL;
    int results_len = 0;

    compute_lps_array(pat, M, lps);

    int i = 0; 
    int j = 0; 
    while ((N - i) >= (M - j)) 
    {
        if (pat[j] == txt[i]) 
        {
            j++;
            i++;
        }

        if (j == M) 
        {
            results_len++;
            results = realloc(results, results_len * sizeof(int));
            results[results_len-1] = i - j;

            j = lps[j - 1];
        }

        else if (i < N && pat[j] != txt[i]) 
        {
            if (j != 0)
            {
                j = lps[j - 1];
            }
            else
            {
                i = i + 1;
            }
        }
    }

    int result = results[results_len-1];
    free(results);

    return results_len == 0 ? -1 : result;
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
        // break up insn into peices by str_tok_r
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
        fprintf(stderr, "Failed to open provided path");
        return 1;
    }

    char ***insn_strs = get_insns(input_fd); 

    for (int i = 0; insn_strs[i] != 0; i++)
    {
        for (int j = 0; insn_strs[i][j] != 0; j++)
        {
            printf("%s ", insn_strs[i][j]);
        }
        printf("\n");
    }


    return 0;   


    abstract_register_state reg_1;
    abstract_register_state reg_2;

    assign_reg(&reg_1, argv[2]);
    assign_reg(&reg_2, argv[3]);

    abstract_register_state state[] = {
        {.mask = SINGLETON, .value = 0},
        reg_1,
        reg_2
    };

    struct bpf_insn test_insn;
    assign_test_insn(&test_insn, argv[1]);

    /* generate and load bpf program */

    bpf_prog prog = gen_prog(state, test_insn);
    if (load_prog(prog, 0) < 0)
    {
        printf("PROGRAM FAILED VERIFICATION: %s\n", strerror(errno));
    }

    /* READ TRACE */

    int fd = open(TRACE_FILE, O_RDONLY);
    if (fd < 0)
    {
        printf("Not able to open trace buffer.\n");
        return EXIT_FAILURE;
    }

    return 0;

}
