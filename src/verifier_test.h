#ifndef _PROG_GEN_H
#define _PROG_GEN_H

#define SINGLETON 0x0
#define FULLY_UNKNOWN 0xffffffffffffffff

#include <linux/bpf.h>

typedef struct abstract_register_state 
{
	unsigned long long value;
	unsigned long long mask; 
 
	signed long long s64_min;
	signed long long s64_max;

	unsigned long long u64_min;
	unsigned long long u64_max;

	signed int s32_min;
	signed int s32_max;

	unsigned int u32_min;
	unsigned int u32_max;
} abstract_register_state;

typedef struct bpf_prog 
{
	int size;
	struct bpf_insn *insns;
} bpf_prog;

#endif
