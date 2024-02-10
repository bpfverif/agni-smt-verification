from z3 import *
import json
from lib_reg_bounds_tracking import *
from packaging import version
import sys

"""
1. Depending on version we need different json offset
2. The jump instructions require a different set up
3. ALU instrucitons need a different setup

arguments: kernel version, operation, reg1, reg2
"""
def main():
    if len(sys.argv) != 5:
        print("usage python3 test_encoding.py <kernel_version> <op_type> \
                <reg1> <reg2>")
        return 1

    kernel_version = sys.argv[1]
    operation = sys.argv[2]
    reg_1 = sys.argv[3]
    reg_2 = sys.argv[4]

    s = Optimize()
    smt_file = f"../bpf-encodings/{kernel_version}/BPF_{operation}.smt2"
    
    abstract_operator = parse_smt2_file(smt_file)
    s.add(abstract_operator)

    in_json_bpf_enc_mapping = []
    out_json_bpf_enc_mapping = []
    with open(smt_file, "r") as file:
        lines = file.readlines()
        in_json_bpf_enc_mapping = lines[-2].strip()
        in_json_bpf_enc_mapping = in_json_bpf_enc_mapping[1:]
        in_json_bpf_enc_mapping = json.loads(in_json_bpf_enc_mapping)

        out_json_bpf_enc_mapping = lines[-1].strip()
        out_json_bpf_enc_mapping = out_json_bpf_enc_mapping[1:]
        out_json_bpf_enc_mapping = json.loads(out_json_bpf_enc_mapping)

    # add in output dst reg and then add quantifer constraint saying that we want the output dst

    input_dst_reg = bpf_register("dst_input0")
    input_src_reg = bpf_register("src_input0")
    output_dst_reg = bpf_register("dst_output0")
    
    json_off = 4 if version.parse(kernel_version) == version.parse("4.14") else 5
    
    # update bv mapping handles no 32-bit valus for version less than 5.73c1
    input_dst_reg.update_bv_mappings(in_json_bpf_enc_mapping["dst_reg"][json_off:],
            kernel_version)
    input_src_reg.update_bv_mappings(in_json_bpf_enc_mapping["src_reg"][json_off:],
    kernel_version)
    output_dst_reg.update_bv_mappings(out_json_bpf_enc_mapping["dst_reg"][json_off:],
            kernel_version)
    
    if reg_1 == "unknown":
        s.add(input_dst_reg.fully_unknown())
    else:
        s.add(input_dst_reg.singleton(int(reg_1)))

    if reg_2 == "unknown":
        s.add(input_src_reg.fully_unknown())
    else:
        s.add(input_src_reg.singleton(int(reg_2)))
    
    if str(s.check()) == "sat": print("1 sat solution found")
    else: print("0 no sat solution found")
        
    print("val    :", s.model()[output_dst_reg.var_off_value])
    print("mask   :", s.model()[output_dst_reg.var_off_mask])

    print("s64_min:", s.model()[output_dst_reg.smin_value])
    print("s64_max:", s.model()[output_dst_reg.smax_value])

    print("u64_min:", s.model()[output_dst_reg.umin_value])
    print("u64_max:", s.model()[output_dst_reg.umax_value])

    print("s32_min:", s.model()[output_dst_reg.s32_min_value])
    print("s32_max:", s.model()[output_dst_reg.s32_max_value])

    print("u32_min:", s.model()[output_dst_reg.u32_min_value])
    print("u32_max:", s.model()[output_dst_reg.u32_max_value])
    
    s.add(output_dst_reg.check_uniqueness(s))
    
    if str(s.check()) == "sat": print("0 not unique") 
    else: print("1 unique") 

if __name__ == "__main__":
    main()
