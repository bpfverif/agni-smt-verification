from z3 import *
import json
from lib_reg_bounds_tracking import *
from packaging import version
import copy
import sys


smt_file = "../bpf-encodings/6.2/BPF_JEQ.smt2"
s = Optimize()
kernel_version = "6.2"

abstract_operator = parse_smt2_file(smt_file)
s.add(abstract_operator)

file = open(smt_file)
lines = file.readlines()
file.close()

in_json_bpf_enc_mapping = []
out_json_bpf_enc_mapping = []

in_json_bpf_enc_mapping = lines[-2].strip()
in_json_bpf_enc_mapping = in_json_bpf_enc_mapping[1:]
in_json_bpf_enc_mapping = json.loads(in_json_bpf_enc_mapping)

out_json_bpf_enc_mapping = lines[-1].strip()
out_json_bpf_enc_mapping = out_json_bpf_enc_mapping[1:]
out_json_bpf_enc_mapping = json.loads(out_json_bpf_enc_mapping)

input_dst_reg = bpf_register("dst_input0")
input_src_reg = bpf_register("src_input0")
output_dst_reg = bpf_register("dst_output0")
output_src_reg = bpf_register("src_output0")
other_output_dst_reg = bpf_register("dst_output1")
other_output_src_reg = bpf_register("src_output1")


json_off = 5

input_dst_reg.update_bv_mappings(in_json_bpf_enc_mapping["dst_reg"][json_off:],
        kernel_version)
input_src_reg.update_bv_mappings(in_json_bpf_enc_mapping["src_reg"][json_off:],
kernel_version)
output_dst_reg.update_bv_mappings(out_json_bpf_enc_mapping["dst_reg"][json_off:],
        kernel_version)
output_src_reg.update_bv_mappings(out_json_bpf_enc_mapping["src_reg"][json_off:],
        kernel_version)
other_output_dst_reg.update_bv_mappings(out_json_bpf_enc_mapping["other_branch_dst_reg"][json_off:],
        kernel_version)
other_output_src_reg.update_bv_mappings(out_json_bpf_enc_mapping["other_branch_src_reg"][json_off:],
        kernel_version)


s.add(input_dst_reg.singleton(10))
s.add(input_src_reg.fully_unknown())

"""
{.mask = SINGLETON, .value = 10},
        {.mask = FULLY_UNKNOWN},
"""

s.check()

print(s.model()[output_dst_reg.var_off_value],
            s.model()[output_dst_reg.var_off_mask],
            s.model()[output_dst_reg.smin_value],
            s.model()[output_dst_reg.smax_value],
            s.model()[output_dst_reg.umin_value],
            s.model()[output_dst_reg.umax_value],
            s.model()[output_dst_reg.s32_min_value],
            s.model()[output_dst_reg.s32_max_value],
            s.model()[output_dst_reg.u32_min_value],
            s.model()[output_dst_reg.u32_max_value], end=" \n")

print(s.model()[output_dst_reg.var_off_value],
            s.model()[output_src_reg.var_off_mask],
            s.model()[output_src_reg.smin_value],
            s.model()[output_src_reg.smax_value],
            s.model()[output_src_reg.umin_value],
            s.model()[output_src_reg.umax_value],
            s.model()[output_src_reg.s32_min_value],
            s.model()[output_src_reg.s32_max_value],
            s.model()[output_src_reg.u32_min_value],
            s.model()[output_src_reg.u32_max_value], end=" \n")

print(s.model()[output_dst_reg.var_off_value],
            s.model()[other_output_dst_reg.var_off_mask],
            s.model()[other_output_dst_reg.smin_value],
            s.model()[other_output_dst_reg.smax_value],
            s.model()[other_output_dst_reg.umin_value],
            s.model()[other_output_dst_reg.umax_value],
            s.model()[other_output_dst_reg.s32_min_value],
            s.model()[other_output_dst_reg.s32_max_value],
            s.model()[other_output_dst_reg.u32_min_value],
            s.model()[other_output_dst_reg.u32_max_value], end=" \n")

print(s.model()[output_dst_reg.var_off_value],
            s.model()[other_output_dst_reg.var_off_mask],
            s.model()[other_output_dst_reg.smin_value],
            s.model()[other_output_dst_reg.smax_value],
            s.model()[other_output_dst_reg.umin_value],
            s.model()[other_output_dst_reg.umax_value],
            s.model()[other_output_dst_reg.s32_min_value],
            s.model()[other_output_dst_reg.s32_max_value],
            s.model()[other_output_dst_reg.u32_min_value],
            s.model()[other_output_dst_reg.u32_max_value], end=" \n")

