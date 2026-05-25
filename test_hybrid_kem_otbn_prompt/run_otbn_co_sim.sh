#!/bin/bash
# ================================================================
# run_otbn_co_sim.sh — Hybrid KEM OTBN RTL+ISS co-simulation
#
# 用法 (在 OpenTitan repo 根目录执行):
#   ./test_hybrid_kem_otbn_prompt/run_otbn_co_sim.sh              # 全部 5 个
#   ./test_hybrid_kem_otbn_prompt/run_otbn_co_sim.sh hkdf         # 单个
#   ./test_hybrid_kem_otbn_prompt/run_otbn_co_sim.sh p256_ecdh
#   ./test_hybrid_kem_otbn_prompt/run_otbn_co_sim.sh mlkem_keypair
#   ./test_hybrid_kem_otbn_prompt/run_otbn_co_sim.sh mlkem_encap
#   ./test_hybrid_kem_otbn_prompt/run_otbn_co_sim.sh mlkem_decap
#
# 前置: FuseSoc 构建 OTBN Verilator 模型 (带 BNMULV v2, ML-KEM 依赖)
#   fusesoc --cores-root=. run --target=sim --setup --build \
#     --flag=bnmulv_ver2 \
#     --mapping=lowrisc:prim_generic:all:0.1 lowrisc:ip:otbn_top_sim \
#     --make_options="-j$(nproc)"
#
# P-256 + HKDF 仅用基线指令, 在 BNMULV v2 硬件上兼容运行.
# ================================================================

set -euo pipefail

REPO_TOP="$(pwd)"
VTOP="${REPO_TOP}/build/lowrisc_ip_otbn_top_sim_0.1/sim-verilator/Votbn_top_sim"

# ---- 测试目标: 短名 → bazel label ----
declare -A TARGETS
TARGETS=(
  [p256_ecdh]="//test_hybrid_kem_otbn_prompt/otbn/p256_ecdh:p256_ecdh"
  [hkdf]="//test_hybrid_kem_otbn_prompt/otbn/hkdf:hkdf_sha3_256"
  [mlkem_keypair]="//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_keypair"
  [mlkem_encap]="//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_encap"
  [mlkem_decap]="//test_hybrid_kem_otbn_prompt/otbn/mlkem768:mlkem768_decap"
)

ORDER=(p256_ecdh hkdf mlkem_keypair mlkem_encap mlkem_decap)

GREEN='\033[1;32m'
RED='\033[1;31m'
BLUE='\033[1;34m'
NC='\033[0m'

SELECTED="${1:-}"

fail() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---- 检查 Verilator 模型 ----
if [[ ! -x "${VTOP}" ]]; then
  fail "Votbn_top_sim not found at ${VTOP}"
  echo "Build: fusesoc --cores-root=. run --target=sim --setup --build \\"
  echo "  --flag=bnmulv_ver2 --mapping=lowrisc:prim_generic:all:0.1 lowrisc:ip:otbn_top_sim"
  exit 1
fi

# ---- 单个测试 ----
run_one() {
  local name="$1"
  local bazel_target="${TARGETS[$name]}"

  # //pkg/sub:target → bazel-bin/pkg/sub/target.elf
  local tmp="${bazel_target#//}"
  local pkg="${tmp%:*}"
  local tgt="${tmp#*:}"
  local elf="${REPO_TOP}/bazel-bin/${pkg}/${tgt}.elf"

  echo -e "${BLUE}===== RTL+ISS: ${name} =====${NC}"

  ./bazelisk.sh build "${bazel_target}" || { fail "${name}: bazel build failed"; return 1; }

  if [[ ! -f "${elf}" ]]; then
    fail "${name}: ELF not found: ${elf}"
    return 1
  fi

  if timeout 120s "${VTOP}" --load-elf="${elf}" 2>&1; then
    echo -e "${GREEN}PASS: ${name} — RTL matches ISS${NC}"
    return 0
  else
    local rc=$?
    if [[ $rc -eq 124 ]]; then
      fail "${name}: timeout (120s)"
    else
      fail "${name}: RTL/ISS mismatch (exit ${rc})"
    fi
    return 1
  fi
}

# ---- 主流程 ----
PASS=0
FAIL=0

if [[ -n "${SELECTED}" ]]; then
  if [[ -z "${TARGETS[$SELECTED]:-}" ]]; then
    echo "Unknown: ${SELECTED}.  Valid: ${ORDER[*]}"
    exit 1
  fi
  run_one "${SELECTED}" && ((PASS++)) || ((FAIL++))
else
  for t in "${ORDER[@]}"; do
    run_one "${t}" && ((PASS++)) || ((FAIL++))
    echo ""
  done
fi

echo -e "${BLUE}===== Results: ${GREEN}${PASS} PASS${NC}, ${RED}${FAIL} FAIL${NC} =====${NC}"
[[ $FAIL -eq 0 ]] || exit 1
