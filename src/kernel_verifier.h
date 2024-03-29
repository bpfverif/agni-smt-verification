#ifndef _KERNEL_VERIFIER_H
#define _KERNEL_VERIFIER_H

#include "libbpf.h"

#define SINGLETON 0x0
#define FULLY_UNKNOWN 0xffffffffffffffff

typedef struct abstract_register_state 
{
	uint64_t value;
	uint64_t mask; 
 
	signed long long s64_min;
	signed long long s64_max;

	uint64_t u64_min;
	uint64_t u64_max;

	signed int s32_min;
	signed int s32_max;

	unsigned int u32_min;
	unsigned int u32_max;
} abstract_register_state;

// Get rid of this in refactor
typedef struct bpf_prog 
{
	int size;
	struct bpf_insn *insns;
} bpf_prog;

#endif
