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

#define ITERS 15
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

int main(int argc, char **argv)
{
    abstract_register_state state[] = {
        {.mask = SINGLETON, .value = 0},
        {.mask = SINGLETON, .value = 10},
        {.mask = FULLY_UNKNOWN},
        // {.mask = SINGLETON, .value = 11},
    };
    
    // JEQ insn
    struct bpf_insn test_insn = BPF_JMP_REG(0x10, BPF_REG_1, BPF_REG_2, 0);

    bpf_prog prog = gen_prog(state, test_insn);
    
    if (load_prog(prog, 0) < 0)
    {
        printf("PROGRAM FAILED VERIFICATION: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
}
