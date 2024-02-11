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

#define BUFSIZE 4096
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
    // only regular instructions assumption (for now)
    prog.insns[num_insns-3] = test_insn;
    prog.insns[num_insns-2] = BPF_MOV64_IMM(BPF_REG_0, 0);
    prog.insns[num_insns-1] = BPF_EXIT_INSN();

    prog.size = num_insns * bpf_insn_size;

    return prog;
}

/*  TODO 
 *  
 *  Check for Errors
 *  - Read through code, identify points of failure
 *  - Checks to make sure errors do not occur
 *
 *  Error Reporting
 *  - specified file or default if no log file provided
 *  - refer to error content/format in notes.md
 *
 *  Expand to test non ALU operations (JMP, SYNC, etc)
 *  - not sure how to do
 *
 *  Multithreaded testing  
 *  - mutex for log fd
 * 
 *  Separate Functions into Different files
 *  - String search functions into separate file
 *
 *  Make output into /bin
 *
 *  Test to make sure error reports are happening when they should be
 *  - can be no errors in this
 */

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
}

unsigned long long *get_verifier_values(char *insn_str, char *reg_1_str, char *reg_2_str)
{
    abstract_register_state reg_1;
    abstract_register_state reg_2;

    assign_reg(&reg_1, reg_1_str);
    assign_reg(&reg_2, reg_2_str);

    abstract_register_state state[] = {
        {.mask = SINGLETON, .value = 0},
        reg_1,
        reg_2
    };

    struct bpf_insn test_insn;
    assign_test_insn(&test_insn, insn_str);
    
    bpf_prog prog = gen_prog(state, test_insn);
    if (load_prog(prog, 0) < 0)
    {
        printf("PROGRAM FAILED VERIFICATION: %s\n", strerror(errno));
    }

    /* BPF STATE */

    int fd = open(TRACE_FILE, O_RDONLY);
    if (fd < 0)
    {
        printf("Not able to open trace buffer.\n");
        return NULL;
    }

    int buf_idx, bytes, tc_size = 0;
    char *trace_content = NULL, buf[BUFSIZE];

    memset(buf, 0, BUFSIZE);
#define TAG_STRING "bpf_state: OUPUT"

    while ((bytes = read(fd, buf, BUFSIZE)) > 0)
    {
        tc_size += bytes;
        trace_content = realloc(trace_content, tc_size);
        memcpy(trace_content + tc_size - bytes, buf, bytes);
    }

    if (bytes < 0)
    {
        printf("Read of trace buffer failed.\n");
        free(trace_content);
        return NULL; 
    }

    trace_content = realloc(trace_content, tc_size + 1);
    trace_content[tc_size] = 0;

    int tc_idx = kmp_search(TAG_STRING, trace_content);
    if (tc_idx > -1) 
    {
        tc_idx = tc_idx + strlen(TAG_STRING);
    }

    int colon_count = 0, i = tc_idx;
    unsigned long long *trace_output_vals = malloc(sizeof(unsigned long long) * 10);
    while (colon_count < 10)
    {
        if (trace_content[i] == ':')
        {
            trace_output_vals[colon_count] = strtoull(trace_content + i + 1, NULL, 10);

            if (colon_count == 6 || colon_count == 7)
            {
                trace_output_vals[colon_count] = trace_output_vals[colon_count] & 
                    0x00000000ffffffff;
            }

            colon_count++;
        }
        i++;

        if (i >= tc_size)
        {
            printf("Content not printed in trace");
            return NULL;
        }
    }

    close(fd);
    free(trace_content);

    return trace_output_vals;
}


unsigned long long *get_py_values(char *insn_str, char *reg_1_str, char *reg_2_str)
{
    char *py_cmd = malloc(1);
    py_cmd[0] = 0;
    char *pyargs[7] = {"python3", "test_encoding.py", "6.2", insn_str, reg_1_str, 
        reg_2_str, NULL};
    int arg_idx;

    for (int i = 0; pyargs[i] != NULL; i++)
    {
        int new_len = strlen(py_cmd) + strlen(pyargs[i]) + 2;
        py_cmd = realloc(py_cmd, new_len);
        strcat(py_cmd, pyargs[i]);
        strcat(py_cmd, " ");
    }
    py_cmd[strlen(py_cmd)-1] = 0;

    int pyfd = fileno(popen(py_cmd,  "r"));

    char *py_content = NULL, buf[BUFSIZE];
    int bytes = read(pyfd, buf, BUFSIZE);
    py_content = malloc(bytes+1);
    py_content[bytes] = 0;
    memcpy(py_content, buf, bytes);
    memset(buf, 0, BUFSIZE);

    int i = 0, colon_count = 0;
    int pc_size = bytes;

    if (py_content[0] - '0' == 0)
    {
        printf("smt solution not found\n");
        return NULL;
        // TODO report error (no satisfying solution) 
    }

    unsigned long long *py_output_vals = malloc(sizeof(unsigned long long) * 10);
    while (colon_count < 10)
    {
        if (py_content[i] == ':')
        {
            py_output_vals[colon_count] = strtoull(py_content + i + 1, NULL, 10);

            if (colon_count == 6 || colon_count == 7)
            {
                py_output_vals[colon_count] = py_output_vals[colon_count] & 
                    0x00000000ffffffff;
            }

            colon_count++;
        }
        i++;

        if (i >= pc_size)
        {
            printf("Content not printed in trace");
            return NULL;
        }
    }

    while (py_content[i-1] != '\n') 
    { 
        i++; 
    }

    if (py_content[i] - '0' == 0)
    {
        printf("smt solution not unique\n");
        return NULL;
        // TODO report error (solution is not unique) 
    }

    return py_output_vals; 
}

void outputs_equal(unsigned long long verifier_vals, unsigned long long py_vals)
{
    if (verifer_vals == NULL || py_vals == NULL)
    {
        return;
    }

    for (int i = 0; i < 10; i++)
    {
        if (py_output_vals[i] != trace_output_vals[i])
        {
            // TODO report error
            return;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        printf("usage: ./verifier_test <ALU ISNS> <reg 1 val> <reg 2 val>\n");
        return EXIT_FAILURE;
    }

    unsigned long long *trace_output_vals = get_verifier_values(argv[1], argv[2], argv[3]);
    unsigned long long *py_output_vals = get_py_values(argv[1], argv[2], argv[3]);
    
    outputs_equal(trace_output_vals, py_output_vals)

    free(trace_output_vals);
    free(py_output_vals);

    return 0;
}
