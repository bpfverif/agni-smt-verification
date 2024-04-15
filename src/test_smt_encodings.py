import subprocess
import os
import sys

def main():
    argv = sys.argv
    argc = len(argv)

    if argc != 4:
        print("usage: python3 test_smt_encodings.py <insns>, <num_insns>, <kern_ver>")
        return 1

    insns = argv[1]
    num_insns = argv[2]
    kern_ver = argv[3]

    input_fp = f"./test{insns.replace(',', '-')}{num_insns}/inputs"
    test_dir = input_fp.split("/")[1]
    ko = f"{test_dir}/kern_outputs"
    so = f"{test_dir}/smt_outputs"

    if not os.path.exists(test_dir):
        os.mkdir(test_dir)

    # generate input
    subprocess.run(["./rand", insns, num_insns, input_fp])

    # generate outputs
    kern_outputs_file = open(ko, "w")
    subprocess.run(["./kernel_verifier", input_fp],
            stdout=kern_outputs_file)
    kern_outputs_file.close()

    smt_outputs_file = open(so, "w")
    subprocess.run(["python3","smt_verifier.py", kern_ver, input_fp],
            stdout=smt_outputs_file)
    smt_outputs_file.close()

    # do comparison with diff

    so = "dt1"
    ko = "dt2"

    diff_result = subprocess.run(
            f"nl {so} > {so}_nl; rm {so}; nl {ko} > {ko}_nl; rm {ko}; diff {so}_nl {ko}_nl",
            stdout=subprocess.PIPE, shell=True)

    # read diff output
    diff_output = str(diff_result.stdout, encoding='utf-8')

    if len(diff_output) == 0:
        print("No difference in output between SMT verifier and kernel verifier.")
        return

    diff_lines = diff_output.split("\n")
    diff_lines = [line for line in diff_lines if len(line) > 0 and line[0].isnumeric()]
    broken_inputs = [int(num) for line in diff_lines for num in line.split("c")[0].split(",")]


    inputs = open(input_fp, "r")
    input_lines = inputs.readlines()
    inputs.close()

    broken_inputs = [input_lines[i-1].strip() for i in broken_inputs]

    print("Broken Instructions:")
    print()
    print(*broken_inputs, sep="\n")


if __name__ == '__main__':
    main()
