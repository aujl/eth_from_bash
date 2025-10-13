#!/usr/bin/env bash
#
# Benchmark the bigint helpers shared through BC_COMMON_FUNCS across the
# existing bc coprocess and an alternative Python backend. Random test vectors
# (seeded from /dev/urandom) are reused for each backend so we can compare
# correctness and wall-clock latency apples-to-apples. The summary table reports
# totals (ms) and per-case averages (µs) for each operation.
#
# Recent baseline (container: Debian bookworm, bc 1.07.1, Python 3.11):
#   - modexp: bc ~9.9 s total / 0.40 s avg, Python ~0.49 s total / 0.020 s avg.
#   - gcd:    bc ~0.31 s total / 0.012 s avg, Python ~0.49 s total / 0.020 s avg.
#   - modinv: bc ~0.39 s total / 0.015 s avg, Python ~0.50 s total / 0.020 s avg.
# Python crushes the heavy modexp workload (~20x faster) while bc holds up on
# gcd/modinv. Future tuning can explore embedding Python for modexp while
# retaining bc for the lighter helpers. For now we keep the stable bc backend
# and land this script so regressions are measurable.
#
set -euo pipefail

NUM_CASES=${NUM_CASES:-25}
BC_FUNCS='define modexp(a,b,n){
  if(n==1) return 0;
  a%=n;
  res=1;
  while(b>0){
    if(b%2==1) res=(res*a)%n;
    a=(a*a)%n;
    b/=2;
  }
  return res;
}
define gcd(a,b){
  auto t;
  while(b!=0){
    t=b;
    b=a%b;
    a=t;
  }
  if(a<0) a=-a;
  return a;
}
define modinv(a,m){
  auto m0,t,q,x0,x1;
  m0=m;
  x0=0;
  x1=1;
  if(m==1) return 0;
  while(a>1){
    q=a/m;
    t=m;
    m=a%m;
    a=t;
    t=x0;
    x0=x1-q*x0;
    x1=t;
  }
  if(x1<0) x1+=m0;
  x1%=m0;
  if(x1<0) x1+=m0;
  return x1;
}'

BC_BACKEND_PID=""
BC_BACKEND_READ_FD=""
BC_BACKEND_WRITE_FD=""

cleanup() {
  if [[ -n "${BC_BACKEND_PID}" ]]; then
    if kill -0 "${BC_BACKEND_PID}" 2>/dev/null; then
      kill "${BC_BACKEND_PID}" 2>/dev/null || true
    fi
    wait "${BC_BACKEND_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

start_bc_backend() {
  if [[ -n "${BC_BACKEND_PID}" ]] && kill -0 "${BC_BACKEND_PID}" 2>/dev/null; then
    return 0
  fi
  if ! command -v bc >/dev/null 2>&1; then
    echo "bc is required for this benchmark" >&2
    exit 1
  fi
  coproc BC_BACKEND { bc; }
  BC_BACKEND_PID=$!
  BC_BACKEND_READ_FD=${BC_BACKEND[0]}
  BC_BACKEND_WRITE_FD=${BC_BACKEND[1]}
  printf 'scale=0\n' >&${BC_BACKEND_WRITE_FD}
  printf 'ibase=10\n' >&${BC_BACKEND_WRITE_FD}
  printf 'obase=10\n' >&${BC_BACKEND_WRITE_FD}
  printf '%s\n' "${BC_FUNCS}" >&${BC_BACKEND_WRITE_FD}
}

bc_eval() {
  local expr="$1"
  printf '%s\n' "${expr}" >&${BC_BACKEND_WRITE_FD}
  local line result=""
  while IFS= read -r line <&${BC_BACKEND_READ_FD}; do
    if [[ "${line}" == *\\ ]]; then
      result+="${line%\\}"
      continue
    fi
    result+="${line}"
    break
  done
  printf '%s' "${result}"
}

format_total_ms() {
  local total_ns="$1"
  awk -v ns="${total_ns}" 'BEGIN { printf "%.3f", ns/1000000 }'
}

format_avg_us() {
  local total_ns="$1"
  local count="$2"
  awk -v ns="${total_ns}" -v cnt="${count}" 'BEGIN { printf "%.3f", (ns/cnt)/1000 }'
}

seed_from_urandom() {
  od -An -tu8 -N8 /dev/urandom | tr -d ' '
}

RNG_SEED=$(seed_from_urandom)
if [[ -z "${RNG_SEED}" ]]; then
  echo "Failed to draw random seed" >&2
  exit 1
fi

# Generate shared test vectors.
mapfile -t RAW_CASES < <(
  python3 - "$NUM_CASES" "$RNG_SEED" <<'PY'
import math
import random
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: python NUM_CASES SEED")
num_cases = int(sys.argv[1])
seed = int(sys.argv[2])
rng = random.Random(seed)

modexp_bits = {
    'base': 1024,
    'exp': 256,
    'mod': 1024,
}

def rand_bits(bits):
    value = rng.getrandbits(bits)
    if value == 0:
        value = 1
    return value

for _ in range(num_cases):
    a = rand_bits(modexp_bits['base'])
    b = rand_bits(modexp_bits['exp'])
    m = rand_bits(modexp_bits['mod']) | 1
    if m < 3:
        m = 3
    print(f"MODEXP {a} {b} {m}")

for _ in range(num_cases):
    a = rand_bits(1024)
    b = rand_bits(1024)
    print(f"GCD {a} {b}")

for _ in range(num_cases):
    m = rand_bits(1024) | 1
    if m < 3:
        m = 3
    a = rand_bits(1024) % m
    if a == 0:
        a = 1
    while math.gcd(a, m) != 1:
        a = (a + 1) % m
        if a == 0:
            a = 1
    print(f"MODINV {a} {m}")
PY
)

if (( ${#RAW_CASES[@]} != NUM_CASES * 3 )); then
  echo "Unexpected number of test vectors" >&2
  exit 1
fi

declare -a MODEXP_CASES=()
declare -a GCD_CASES=()
declare -a MODINV_CASES=()

for entry in "${RAW_CASES[@]}"; do
  IFS=' ' read -r tag rest <<<"${entry}"
  case "${tag}" in
    MODEXP)
      MODEXP_CASES+=("${entry#MODEXP }")
      ;;
    GCD)
      GCD_CASES+=("${entry#GCD }")
      ;;
    MODINV)
      MODINV_CASES+=("${entry#MODINV }")
      ;;
    *)
      echo "Unknown case tag: ${tag}" >&2
      exit 1
      ;;
  esac
done

start_bc_backend

declare -a MODEXP_BC_RESULTS=()
declare -a GCD_BC_RESULTS=()
declare -a MODINV_BC_RESULTS=()

declare -a MODEXP_PY_RESULTS=()
declare -a GCD_PY_RESULTS=()
declare -a MODINV_PY_RESULTS=()

bc_modexp_start=$(date +%s%N)
for case in "${MODEXP_CASES[@]}"; do
  IFS=' ' read -r a b m <<<"${case}"
  MODEXP_BC_RESULTS+=("$(bc_eval "modexp(${a},${b},${m})")")
done
bc_modexp_total=$(( $(date +%s%N) - bc_modexp_start ))

py_modexp_start=$(date +%s%N)
mapfile -t MODEXP_PY_RESULTS < <(
  printf '%s\n' "${MODEXP_CASES[@]}" | python3 -c 'import sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    a_s, b_s, m_s = line.split()
    a = int(a_s)
    b = int(b_s)
    m = int(m_s)
    print(pow(a, b, m))'
)
py_modexp_total=$(( $(date +%s%N) - py_modexp_start ))

bc_gcd_start=$(date +%s%N)
for case in "${GCD_CASES[@]}"; do
  IFS=' ' read -r a b <<<"${case}"
  GCD_BC_RESULTS+=("$(bc_eval "gcd(${a},${b})")")
done
bc_gcd_total=$(( $(date +%s%N) - bc_gcd_start ))

py_gcd_start=$(date +%s%N)
mapfile -t GCD_PY_RESULTS < <(
  printf '%s\n' "${GCD_CASES[@]}" | python3 -c 'import math
import sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    a_s, b_s = line.split()
    a = int(a_s)
    b = int(b_s)
    print(math.gcd(a, b))'
)
py_gcd_total=$(( $(date +%s%N) - py_gcd_start ))

bc_modinv_start=$(date +%s%N)
for case in "${MODINV_CASES[@]}"; do
  IFS=' ' read -r a m <<<"${case}"
  MODINV_BC_RESULTS+=("$(bc_eval "modinv(${a},${m})")")
done
bc_modinv_total=$(( $(date +%s%N) - bc_modinv_start ))

py_modinv_start=$(date +%s%N)
mapfile -t MODINV_PY_RESULTS < <(
  printf '%s\n' "${MODINV_CASES[@]}" | python3 -c 'import sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    a_s, m_s = line.split()
    a = int(a_s)
    m = int(m_s)
    print(pow(a, -1, m))'
)
py_modinv_total=$(( $(date +%s%N) - py_modinv_start ))

compare_results() {
  local -n arr_a=$1
  local -n arr_b=$2
  if (( ${#arr_a[@]} != ${#arr_b[@]} )); then
    echo "length-mismatch"
    return
  fi
  local mismatches=0
  for idx in "${!arr_a[@]}"; do
    if [[ "${arr_a[idx]}" != "${arr_b[idx]}" ]]; then
      ((mismatches++))
    fi
  done
  if (( mismatches == 0 )); then
    echo "ok"
  else
    echo "mismatch(${mismatches})"
  fi
}

modepx_match=$(compare_results MODEXP_BC_RESULTS MODEXP_PY_RESULTS)
gcd_match=$(compare_results GCD_BC_RESULTS GCD_PY_RESULTS)
modinv_match=$(compare_results MODINV_BC_RESULTS MODINV_PY_RESULTS)

printf 'Random seed: %s\n' "${RNG_SEED}"
printf 'Cases per operation: %d\n\n' "${NUM_CASES}"

printf '%-8s | %5s | %12s | %12s | %12s | %12s | %s\n' "Op" "Cases" "bc total (ms)" "py total (ms)" "bc avg (µs)" "py avg (µs)" "match"
printf '%s\n' "--------------------------------------------------------------------------------------------------------------"
printf '%-8s | %5d | %12s | %12s | %12s | %12s | %s\n' "modexp" "${NUM_CASES}" "$(format_total_ms "${bc_modexp_total}")" "$(format_total_ms "${py_modexp_total}")" "$(format_avg_us "${bc_modexp_total}" "${NUM_CASES}")" "$(format_avg_us "${py_modexp_total}" "${NUM_CASES}")" "${modepx_match}"
printf '%-8s | %5d | %12s | %12s | %12s | %12s | %s\n' "gcd" "${NUM_CASES}" "$(format_total_ms "${bc_gcd_total}")" "$(format_total_ms "${py_gcd_total}")" "$(format_avg_us "${bc_gcd_total}" "${NUM_CASES}")" "$(format_avg_us "${py_gcd_total}" "${NUM_CASES}")" "${gcd_match}"
printf '%-8s | %5d | %12s | %12s | %12s | %12s | %s\n' "modinv" "${NUM_CASES}" "$(format_total_ms "${bc_modinv_total}")" "$(format_total_ms "${py_modinv_total}")" "$(format_avg_us "${bc_modinv_total}" "${NUM_CASES}")" "$(format_avg_us "${py_modinv_total}" "${NUM_CASES}")" "${modinv_match}"
