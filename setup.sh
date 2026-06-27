#!/bin/bash
# Clone the upstream public benchmarks this harness scores Kaizen against.
# They are pinned to a commit for reproducibility. The Kaizen-corpus benchmark
# (memory integrity) needs no external data, and CyberSecEval is fetched at runtime.
set -e
mkdir -p benchmarks && cd benchmarks

clone() {  # repo, dir, commit
  [ -d "$2" ] && { echo "$2 already present"; return; }
  git clone --quiet "$1" "$2"
  git -C "$2" checkout --quiet "$3" 2>/dev/null || echo "  (using default branch for $2)"
}

clone https://github.com/luckyPipewrench/agent-egress-bench agent-egress-bench HEAD
clone https://github.com/uiuc-kang-lab/InjecAgent InjecAgent HEAD
clone https://github.com/ethz-spylab/agentdojo agentdojo HEAD

echo "benchmarks ready in ./benchmarks"
