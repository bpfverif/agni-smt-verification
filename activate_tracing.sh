#!/bin/bash

echo 1 > "/sys/kernel/debug/tracing/events/bpf_state/bpf_state/enable"
