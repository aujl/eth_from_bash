#!/usr/bin/env bash
#
# Benchmark the bigint helpers shared through BC_COMMON_FUNCS against a shell
# reference implementation that exercises the same operations via bc. Random
# test vectors (seeded from /dev/urandom or RNG_SEED) are reused for each
# backend so we can compare correctness and wall-clock latency apples-to-apples.
# The summary table reports totals (ms) and per-case averages (µs) for each
# operation.
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

# Deterministic RNG based on an LCG so callers can replay runs.
RNG_MOD="340282366920938463463374607431768211456" # 2^128
RNG_A="6364136223846793005"
RNG_C="1442695040888963407"
RNG_STATE=""

rng_init() {
  local seed="$1"
  RNG_STATE=$(bc_eval "(${seed}) % ${RNG_MOD}")
}

rng_next_u128() {
  RNG_STATE=$(bc_eval "((${RNG_A} * ${RNG_STATE}) + ${RNG_C}) % ${RNG_MOD}")
  printf '%s\n' "${RNG_STATE}"
}

rand_bits() {
  local bits=$1
  local remaining=$bits
  local value="0"
  while (( remaining > 0 )); do
    local chunk=$(( remaining > 128 ? 128 : remaining ))
    local next_state
    next_state=$(rng_next_u128)
    local chunk_value
    chunk_value=$(bc_eval "${next_state} % (2^${chunk})")
    value=$(bc_eval "(${value} * (2^${chunk})) + ${chunk_value}")
    remaining=$(( remaining - chunk ))
  done
  if [[ $(bc_eval "${value} == 0") == "1" ]]; then
    value="1"
  fi
  printf '%s\n' "${value}"
}

rand_odd_modulus() {
  local bits=$1
  local candidate
  while :; do
    candidate=$(rand_bits "${bits}")
    if [[ $(bc_eval "${candidate} < 3") == "1" ]]; then
      candidate="3"
    fi
    if [[ $(bc_eval "${candidate} % 2") == "0" ]]; then
      candidate=$(bc_eval "${candidate} + 1")
    fi
    if [[ $(bc_eval "${candidate} % 2") == "1" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done
}

rand_modexp_case() {
  local a b m
  a=$(rand_bits 1024)
  b=$(rand_bits 256)
  m=$(rand_odd_modulus 1024)
  printf '%s %s %s\n' "${a}" "${b}" "${m}"
}

rand_gcd_case() {
  local a b
  a=$(rand_bits 1024)
  b=$(rand_bits 1024)
  printf '%s %s\n' "${a}" "${b}"
}

rand_modinv_case() {
  local m a
  m=$(rand_odd_modulus 1024)
  a=$(bc_eval "$(rand_bits 1024) % ${m}")
  if [[ $(bc_eval "${a} == 0") == "1" ]]; then
    a="1"
  fi
  while [[ $(bc_eval "gcd(${a},${m})") != "1" ]]; do
    a=$(bc_eval "(${a} + 1) % ${m}")
    if [[ $(bc_eval "${a} == 0") == "1" ]]; then
      a="1"
    fi
  done
  printf '%s %s\n' "${a}" "${m}"
}

shell_modexp() {
  local a="$1" b="$2" m="$3"
  if [[ $(bc_eval "${m} == 1") == "1" ]]; then
    printf '0\n'
    return
  fi
  local base
  base=$(bc_eval "${a} % ${m}")
  local result="1"
  local exp="${b}"
  while [[ $(bc_eval "${exp} > 0") == "1" ]]; do
    if [[ $(bc_eval "${exp} % 2") == "1" ]]; then
      result=$(bc_eval "(${result} * ${base}) % ${m}")
    fi
    exp=$(bc_eval "${exp} / 2")
    base=$(bc_eval "(${base} * ${base}) % ${m}")
  done
  printf '%s\n' "${result}"
}

shell_gcd() {
  local a="$1" b="$2"
  while [[ $(bc_eval "${b} != 0") == "1" ]]; do
    local t="${b}"
    b=$(bc_eval "${a} % ${b}")
    a="${t}"
  done
  if [[ $(bc_eval "${a} < 0") == "1" ]]; then
    a=$(bc_eval "-${a}")
  fi
  printf '%s\n' "${a}"
}

shell_modinv() {
  local a="$1" m="$2"
  if [[ $(bc_eval "${m} == 1") == "1" ]]; then
    printf '0\n'
    return
  fi
  local m0="${m}"
  local x0="0"
  local x1="1"
  local aa="${a}"
  local mm="${m}"
  while [[ $(bc_eval "${aa} > 1") == "1" ]]; do
    local q
    q=$(bc_eval "${aa} / ${mm}")
    local t="${mm}"
    mm=$(bc_eval "${aa} % ${mm}")
    aa="${t}"
    t="${x0}"
    x0=$(bc_eval "${x1} - ${q} * ${x0}")
    x1="${t}"
  done
  if [[ $(bc_eval "${x1} < 0") == "1" ]]; then
    x1=$(bc_eval "${x1} + ${m0}")
  fi
  x1=$(bc_eval "${x1} % ${m0}")
  if [[ $(bc_eval "${x1} < 0") == "1" ]]; then
    x1=$(bc_eval "${x1} + ${m0}")
  fi
  printf '%s\n' "${x1}"
}

RNG_SEED=${RNG_SEED:-$(seed_from_urandom)}
if [[ -z "${RNG_SEED}" ]]; then
  echo "Failed to draw random seed" >&2
  exit 1
fi
if [[ ! "${RNG_SEED}" =~ ^[0-9]+$ ]]; then
  echo "RNG_SEED must be a non-negative integer" >&2
  exit 1
fi

start_bc_backend
rng_init "${RNG_SEED}"

MODEXP_CASES=()
GCD_CASES=()
MODINV_CASES=()

for ((i = 0; i < NUM_CASES; i++)); do
  MODEXP_CASES+=("$(rand_modexp_case)")
  GCD_CASES+=("$(rand_gcd_case)")
  MODINV_CASES+=("$(rand_modinv_case)")
done

MODEXP_BC_RESULTS=()
GCD_BC_RESULTS=()
MODINV_BC_RESULTS=()

MODEXP_SH_RESULTS=()
GCD_SH_RESULTS=()
MODINV_SH_RESULTS=()

bc_modexp_start=$(date +%s%N)
for case in "${MODEXP_CASES[@]}"; do
  IFS=' ' read -r a b m <<<"${case}"
  MODEXP_BC_RESULTS+=("$(bc_eval "modexp(${a},${b},${m})")")

done
bc_modexp_total=$(( $(date +%s%N) - bc_modexp_start ))

sh_modexp_start=$(date +%s%N)
for case in "${MODEXP_CASES[@]}"; do
  IFS=' ' read -r a b m <<<"${case}"
  MODEXP_SH_RESULTS+=("$(shell_modexp "${a}" "${b}" "${m}")")

done
sh_modexp_total=$(( $(date +%s%N) - sh_modexp_start ))

bc_gcd_start=$(date +%s%N)
for case in "${GCD_CASES[@]}"; do
  IFS=' ' read -r a b <<<"${case}"
  GCD_BC_RESULTS+=("$(bc_eval "gcd(${a},${b})")")

done
bc_gcd_total=$(( $(date +%s%N) - bc_gcd_start ))

sh_gcd_start=$(date +%s%N)
for case in "${GCD_CASES[@]}"; do
  IFS=' ' read -r a b <<<"${case}"
  GCD_SH_RESULTS+=("$(shell_gcd "${a}" "${b}")")

done
sh_gcd_total=$(( $(date +%s%N) - sh_gcd_start ))

bc_modinv_start=$(date +%s%N)
for case in "${MODINV_CASES[@]}"; do
  IFS=' ' read -r a m <<<"${case}"
  MODINV_BC_RESULTS+=("$(bc_eval "modinv(${a},${m})")")

done
bc_modinv_total=$(( $(date +%s%N) - bc_modinv_start ))

sh_modinv_start=$(date +%s%N)
for case in "${MODINV_CASES[@]}"; do
  IFS=' ' read -r a m <<<"${case}"
  MODINV_SH_RESULTS+=("$(shell_modinv "${a}" "${m}")")

done
sh_modinv_total=$(( $(date +%s%N) - sh_modinv_start ))

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

modexp_match=$(compare_results MODEXP_BC_RESULTS MODEXP_SH_RESULTS)
gcd_match=$(compare_results GCD_BC_RESULTS GCD_SH_RESULTS)
modinv_match=$(compare_results MODINV_BC_RESULTS MODINV_SH_RESULTS)

printf 'Random seed: %s\n' "${RNG_SEED}"
printf 'Cases per operation: %d\n\n' "${NUM_CASES}"

printf '%-8s | %5s | %12s | %12s | %12s | %12s | %s\n' "Op" "Cases" "bc total (ms)" "sh total (ms)" "bc avg (µs)" "sh avg (µs)" "match"
printf '%s\n' "--------------------------------------------------------------------------------------------------------------"
printf '%-8s | %5d | %12s | %12s | %12s | %12s | %s\n' "modexp" "${NUM_CASES}" "$(format_total_ms "${bc_modexp_total}")" "$(format_total_ms "${sh_modexp_total}")" "$(format_avg_us "${bc_modexp_total}" "${NUM_CASES}")" "$(format_avg_us "${sh_modexp_total}" "${NUM_CASES}")" "${modexp_match}"
printf '%-8s | %5d | %12s | %12s | %12s | %12s | %s\n' "gcd" "${NUM_CASES}" "$(format_total_ms "${bc_gcd_total}")" "$(format_total_ms "${sh_gcd_total}")" "$(format_avg_us "${bc_gcd_total}" "${NUM_CASES}")" "$(format_avg_us "${sh_gcd_total}" "${NUM_CASES}")" "${gcd_match}"
printf '%-8s | %5d | %12s | %12s | %12s | %12s | %s\n' "modinv" "${NUM_CASES}" "$(format_total_ms "${bc_modinv_total}")" "$(format_total_ms "${sh_modinv_total}")" "$(format_avg_us "${bc_modinv_total}" "${NUM_CASES}")" "$(format_avg_us "${sh_modinv_total}" "${NUM_CASES}")" "${modinv_match}"
