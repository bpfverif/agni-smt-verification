#!/bin/bash

echo 1 > "/sys/kernel/debug/tracing/events/bpf_state/bpf_state/enable"
echo 1 > "/sys/kernel/debug/tracing/events/bpf_state_jc/bpf_state_jc/enable"
