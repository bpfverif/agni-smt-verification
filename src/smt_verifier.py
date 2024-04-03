from z3 import *
import json
from lib_reg_bounds_tracking import *
from packaging import version
import copy
import sys

"""
1. Depending on version we need different json offset
2. The jump instructions require a different set up
3. ALU instrucitons need a different setup

arguments: kernel version, operation, reg1, reg2
"""

optimizers = {}

def twos_comp(val, bits):
    if (val & (1 << (bits - 1))) != 0:
        val = val - (1 << bits)
    return val


def get_smt_output(insn, reg_1, reg_2):
    original_s, input_dst_reg, input_src_reg, output_dst_reg = optimizers.get(insn, None)

    if original_s == None:
        print("insn not recognized")
        os.exit(1)

    s = Optimize()

    s.assert_exprs(original_s.assertions())

    if reg_1 == "unknown":
        s.add(input_dst_reg.fully_unknown())
    else:
        s.add(input_dst_reg.singleton(int(reg_1)))

    if reg_2 == "unknown":
        s.add(input_src_reg.fully_unknown())
    else:
        s.add(input_src_reg.singleton(int(reg_2)))

    s.add(output_dst_reg.check_uniqueness(s))

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

def main():
    if len(sys.argv) != 3:
        print("usage python3 test_encoding.py <kernel_version> <input_path>")
        return 1

    kernel_version = sys.argv[1]
    input_path = sys.argv[2]

    smt_dir = f"../bpf-encodings/{kernel_version}"
    smt_files = [
            f for f in os.listdir(smt_dir) if os.path.isfile(os.path.join(smt_dir, f))
            ]
    smt_files = [os.path.join(smt_dir, f) for f in smt_files]

    for smt_file in smt_files:
        insn_name = smt_file[smt_file.find("_")+1:-5]

        if 'J' in insn_name or insn_name == 'SYNC':
            continue

        s = Optimize()

        abstract_operator = parse_smt2_file(smt_file)
        s.add(abstract_operator)

        file = open(smt_file, "r")
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

        json_off = 4 if version.parse(kernel_version) == version.parse("4.14") else 5

        input_dst_reg.update_bv_mappings(in_json_bpf_enc_mapping["dst_reg"][json_off:],
                kernel_version)
        input_src_reg.update_bv_mappings(in_json_bpf_enc_mapping["src_reg"][json_off:],
        kernel_version)
        output_dst_reg.update_bv_mappings(out_json_bpf_enc_mapping["dst_reg"][json_off:],
                kernel_version)

        optimizers[insn_name] = [s, input_dst_reg, input_src_reg, output_dst_reg]

    input_file = open(input_path, "r")
    for input_line in input_file.readlines():
        insn, reg_1, reg_2 = input_line.strip().split(" ")
        get_smt_output(insn, reg_1, reg_2)

if __name__ == "__main__":
    main()
