import subprocess
import os
import sys

def main():
    argv = sys.argv
    argc = len(argv)

    if argc != 4:
        print("usage: python3 test_smt_encodings.py <insns>, <num_insns>, <kern_ver>")

    insns = argv[1]
    num_insns = argv[2]
    kern_ver = argv[3]

    input_fp = f"./test{insns.replace(',', '-')}{num_insns}/inputs"
    test_dir = input_fp.split("/")[1]

    if not os.path.exists(test_dir):
        os.mkdir(test_dir)

    # generate input
    subprocess.run(["./rand", insns, num_insns, input_fp])

    # generate outputs
    kern_outputs_file = open(f"{test_dir}/kern_outputs", "w")
    subprocess.run(["./kernel_verifier", input_fp],
            stdout=kern_outputs_file)
    kern_outputs_file.close()

    smt_outputs_file = open(f"{test_dir}/smt_outputs", "w")
    subprocess.run(["python3","smt_verifier.py", kern_ver, input_fp],
            stdout=smt_outputs_file)
    smt_outputs_file.close()

    # do comparison with diff
    diff_result = subprocess.run([
            "diff",
            f"{test_dir}/smt_outputs",
            f"{test_dir}/kern_outputs"
        ], stdout=subprocess.PIPE)

    # read diff output
    diff_output = str(diff_result.stdout, encoding='utf-8')

    if len(diff_output) == 0:
        print("No difference in output between SMT verifier and kernel verifier.")
    else:
        print("Difference in output between SMT verifier and kernel verifier:")
        print()
        print(diff_output)

if __name__ == '__main__':
    main()
