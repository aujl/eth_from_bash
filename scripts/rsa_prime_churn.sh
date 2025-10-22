#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CRYPTO_SIGN="${ROOT_DIR}/bin/crypto-sign"

usage() {
  cat <<'USAGE'
Usage: rsa_prime_churn.sh [--bits N] [--exponent E]

Measure bc invocation churn while generating an RSA keypair. The helper traces
internal bc usage via CRYPTO_SIGN_TRACE_CHURN=1 and reports aggregate counts.
USAGE
}

bits=512
exponent=65537

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bits)
      [[ $# -lt 2 ]] && { usage >&2; exit 1; }
      bits="$2"
      shift 2
      ;;
    --exponent)
      [[ $# -lt 2 ]] && { usage >&2; exit 1; }
      exponent="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! [[ "${bits}" =~ ^[0-9]+$ ]] || (( bits < 32 )); then
  echo "--bits must be an integer >= 32" >&2
  exit 1
fi
if ! [[ "${exponent}" =~ ^[0-9]+$ ]] || (( exponent < 3 )); then
  echo "--exponent must be an odd integer >= 3" >&2
  exit 1
fi
if (( exponent % 2 == 0 )); then
  echo "--exponent must be odd" >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

priv_path="${work_dir}/trace_priv.pem"
pub_path="${work_dir}/trace_pub.pem"
log_path="${work_dir}/trace.log"
events_path="${work_dir}/trace_events.log"

show_progress() {
  local target_pid="$1"
  local last_line=""
  while kill -0 "${target_pid}" 2>/dev/null; do
    if [[ -f "${events_path}" ]]; then
      local bc_simple_count bc_eval_count generate_count
      bc_simple_count=$(grep -c '^bc_simple$' "${events_path}" 2>/dev/null || true)
      bc_eval_count=$(grep -c '^bc_eval_common$' "${events_path}" 2>/dev/null || true)
      generate_count=$(grep -c '^generate_prime_dec$' "${events_path}" 2>/dev/null || true)
      printf '\rProgress: bc_simple=%s bc_eval_common=%s generate_prime_dec=%s' \
        "${bc_simple_count}" "${bc_eval_count}" "${generate_count}" >&2
      last_line=$(printf 'Progress: bc_simple=%s bc_eval_common=%s generate_prime_dec=%s' \
        "${bc_simple_count}" "${bc_eval_count}" "${generate_count}")
    fi
    sleep 1
  done
  if [[ -n "${last_line}" ]]; then
    printf '\r%*s\r' "${#last_line}" '' >&2
  fi
}

start_ns="$(date +%s%N)"
CRYPTO_SIGN_TRACE_CHURN=1 \
CRYPTO_SIGN_TRACE_FILE_PATH="${events_path}" \
"${CRYPTO_SIGN}" rsa-generate --bits "${bits}" \
  --exponent "${exponent}" --private-out "${priv_path}" --public-out "${pub_path}" \
  1>/dev/null 2>"${log_path}" &
crypto_pid=$!
progress_pid=""
if [[ -t 2 ]]; then
  show_progress "${crypto_pid}" &
  progress_pid=$!
fi
if ! wait "${crypto_pid}"; then
  if [[ -n "${progress_pid}" ]]; then
    wait "${progress_pid}" 2>/dev/null || true
  fi
  echo "rsa-generate failed; see ${log_path}" >&2
  exit 1
fi
if [[ -n "${progress_pid}" ]]; then
  wait "${progress_pid}" 2>/dev/null || true
fi
end_ns="$(date +%s%N)"

rm -f "${priv_path}" "${pub_path}"

declare -A counts=(
  [bc_simple]=0
  [bc_eval_common]=0
  [generate_prime_dec]=0
)

while IFS='=' read -r key value; do
  if [[ "${key}" == trace:* ]]; then
    local_key="${key#trace:}"
    if [[ -n "${counts[$local_key]+_}" ]]; then
      counts["${local_key}"]="${value}"
    fi
  fi
done <"${log_path}"

duration_ns=$(( end_ns - start_ns ))
duration_ms=$(( duration_ns / 1000000 ))

printf 'bits=%s\n' "${bits}"
printf 'exponent=%s\n' "${exponent}"
printf 'duration_ms=%s\n' "${duration_ms}"
printf 'bc_simple=%s\n' "${counts[bc_simple]}"
printf 'bc_eval_common=%s\n' "${counts[bc_eval_common]}"
printf 'generate_prime_dec=%s\n' "${counts[generate_prime_dec]}"
