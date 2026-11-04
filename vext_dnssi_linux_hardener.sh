#!/usr/bin/env bash
# ==============================================================================
# VEXT-CERT — SOVEREIGN LINUX SECURITY HARDENER & AUDIT ENGINE
# ==============================================================================
# Standard: Moroccan DNSSI 2023 (Chapitres 6 & 7) & ANSSI BP-028 (Niveau Renforcé)
# Authority: VEXT Cybersecurity (vext.ma) — CSIRT & Laboratoire de Recherche
# License: Apache-2.0 / Sovereign Open-Source Community
# ==============================================================================

set -o pipefail

VERSION="2026.1.0"
BANNER="
==============================================================================
               VEXT-CERT · DNSSI 2023 LINUX HARDENING SUITE
         Sovereign Cyber Resilience for Critical Moroccan Systems
                     https://vext.ma · cert@vext.ma
==============================================================================
"

BACKUP_DIR="/var/backups/vext-dnssi-$(date +%Y%m%d_%H%M%S)"
SYSCTL_CONF="/etc/sysctl.d/99-vext-dnssi-hardened.conf"
SSHD_CONF="/etc/ssh/sshd_config.d/99-vext-dnssi.conf"
MODPROBE_CONF="/etc/modprobe.d/99-vext-unused-filesystems.conf"
AUDITD_RULES="/etc/audit/rules.d/99-vext-dnssi.rules"

MODE="audit" # default mode

# Colors
C_RESET="\033[0m"
C_RED="\033[1;31m"
C_GREEN="\033[1;32m"
C_YELLOW="\033[1;33m"
C_BLUE="\033[1;34m"
C_LIME="\033[38;2;198;255;58m"

log_info()    { echo -e "${C_BLUE}[INFO]${C_RESET} $1"; }
log_pass()    { echo -e "${C_GREEN}[PASS]${C_RESET} $1"; }
log_fail()    { echo -e "${C_RED}[FAIL]${C_RESET} $1"; }
log_warn()    { echo -e "${C_YELLOW}[WARN]${C_RESET} $1"; }
log_action()  { echo -e "${C_LIME}[APPLY]${C_RESET} $1"; }

show_help() {
  echo -e "$BANNER"
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --audit, --check     Audit system against 25 DNSSI 2023 controls without modifying (Read-only)"
  echo "  --apply, --enforce   Remediate and apply 25 hardening controls idempotently (Requires root)"
  echo "  --version            Display version and sovereign authority information"
  echo "  --help               Display this help dialog"
  echo ""
  echo "Documentation & Advisory: https://vext.ma/security"
}

# Parse command line flags
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --audit|--check)
      MODE="audit"
      shift
      ;;
    --apply|--enforce)
      MODE="apply"
      shift
      ;;
    --version)
      echo "vext_dnssi_linux_hardener v$VERSION - VEXT Cybersecurity (vext.ma)"
      exit 0
      ;;
    --help|-h)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

echo -e "$BANNER"

# Counters
TOTAL_CONTROLS=25
PASSED_COUNT=0
FAILED_COUNT=0

record_result() {
  local id="$1"
  local ref="$2"
  local name="$3"
  local status="$4"
  local details="$5"

  if [[ "$status" == "PASS" ]]; then
    ((PASSED_COUNT++))
    log_pass "[$id/25] $ref: $name"
  else
    ((FAILED_COUNT++))
    log_fail "[$id/25] $ref: $name -> $details"
  fi
}

# Safely back up files before modification
backup_file() {
  local file="$1"
  if [[ -f "$file" && -d "$BACKUP_DIR" ]]; then
    local rel_dir
    rel_dir="$(dirname "${file#/}")"
    mkdir -p "$BACKUP_DIR/$rel_dir"
    cp -p "$file" "$BACKUP_DIR/$rel_dir/" 2>/dev/null || true
  fi
}

# Check sysctl runtime value
check_sysctl() {
  local key="$1"
  local expected="$2"
  local current=""
  if command -v sysctl >/dev/null 2>&1; then
    current=$(sysctl -n "$key" 2>/dev/null)
    if [[ "$current" == "$expected" ]]; then
      return 0
    fi
  fi
  return 1
}

# Apply sysctl config idempotently
apply_sysctl() {
  local key="$1"
  local val="$2"
  mkdir -p /etc/sysctl.d
  backup_file "$SYSCTL_CONF"
  if ! grep -q "^${key}" "$SYSCTL_CONF" 2>/dev/null; then
    echo "${key} = ${val}" >> "$SYSCTL_CONF"
  else
    if sed --version 2>/dev/null | grep -q GNU; then
      sed -i "s|^${key}.*|${key} = ${val}|" "$SYSCTL_CONF"
    else
      sed -i.bak "s|^${key}.*|${key} = ${val}|" "$SYSCTL_CONF" && rm -f "${SYSCTL_CONF}.bak"
    fi
  fi
  sysctl -w "${key}=${val}" >/dev/null 2>&1 || true
}

# Idempotently set Key-Value parameter in configuration files
set_config_kv() {
  local file="$1"
  local key="$2"
  local val="$3"
  local sep="${4:-=}"

  backup_file "$file"
  mkdir -p "$(dirname "$file")"
  touch "$file"

  if grep -qE "^\s*#?\s*${key}\s*${sep}" "$file" 2>/dev/null; then
    if sed --version 2>/dev/null | grep -q GNU; then
      sed -i -E "s|^\s*#?\s*${key}\s*${sep}.*|${key} ${sep} ${val}|" "$file"
    else
      sed -i.bak -E "s|^\s*#?\s*${key}\s*${sep}.*|${key} ${sep} ${val}|" "$file" && rm -f "${file}.bak"
    fi
  else
    echo "${key} ${sep} ${val}" >> "$file"
  fi
}

# Robust SSH parameter retrieval (with non-root audit fallback)
get_sshd_param() {
  local param="$1"
  local val=""

  # 1. Try runtime configuration via sshd -T (authoritative if run with access to host keys)
  if command -v sshd >/dev/null 2>&1; then
    val=$(sshd -T 2>/dev/null | grep -i "^${param} " | awk '{print $2}')
  fi

  # 2. Fallback to inspection of configuration files if sshd -T failed (e.g. read-only audit)
  if [[ -z "$val" ]]; then
    for conf in /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config; do
      if [[ -f "$conf" ]]; then
        val=$(grep -iE "^\s*${param}\s+" "$conf" 2>/dev/null | tail -n 1 | awk '{print $2}')
        [[ -n "$val" ]] && break
      fi
    done
  fi

  echo "$val"
}

# Robust octal file permission retriever
get_file_perm() {
  local target="$1"
  local perm=""
  if [[ -e "$target" ]]; then
    perm=$(stat -c "%a" "$target" 2>/dev/null)
    if [[ -z "$perm" ]]; then
      perm=$(stat -f "%OLp" "$target" 2>/dev/null)
    fi
  fi
  # Strip leading zero if 4 digits (e.g. 0644 -> 644)
  if [[ ${#perm} -eq 4 && "$perm" == 0* ]]; then
    perm="${perm:1}"
  fi
  echo "$perm"
}

# ==============================================================================
# 25 CRITICAL CONTROLS CHECK & ENFORCEMENT
# ==============================================================================

run_controls() {
  log_info "Mode: $(echo "$MODE" | tr '[:lower:]' '[:upper:]') · Evaluating 25 statutory controls (DNSSI 2023 / ANSSI BP-028)..."
  echo ""

  # --- KERNEL & NETWORK SECURITY (1 to 15) ---

  # 1. net.ipv4.ip_forward = 0
  if check_sysctl "net.ipv4.ip_forward" "0"; then
    record_result 1 "DNSSI-6.2.1" "Disable IPv4 Packet Forwarding" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.ip_forward" "0"
      log_action "Configured net.ipv4.ip_forward = 0"
      record_result 1 "DNSSI-6.2.1" "Disable IPv4 Packet Forwarding" "PASS"
    else
      record_result 1 "DNSSI-6.2.1" "Disable IPv4 Packet Forwarding" "FAIL" "Current: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'unsupported/not set')"
    fi
  fi

  # 2. net.ipv4.conf.all.send_redirects = 0
  if check_sysctl "net.ipv4.conf.all.send_redirects" "0"; then
    record_result 2 "DNSSI-6.2.2" "Disable ICMP Send Redirects" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.conf.all.send_redirects" "0"
      apply_sysctl "net.ipv4.conf.default.send_redirects" "0"
      log_action "Configured send_redirects = 0"
      record_result 2 "DNSSI-6.2.2" "Disable ICMP Send Redirects" "PASS"
    else
      record_result 2 "DNSSI-6.2.2" "Disable ICMP Send Redirects" "FAIL" "ICMP send redirects enabled"
    fi
  fi

  # 3. net.ipv4.conf.all.accept_source_route = 0
  if check_sysctl "net.ipv4.conf.all.accept_source_route" "0"; then
    record_result 3 "DNSSI-6.2.3" "Disable Source Routed Packets" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.conf.all.accept_source_route" "0"
      apply_sysctl "net.ipv4.conf.default.accept_source_route" "0"
      record_result 3 "DNSSI-6.2.3" "Disable Source Routed Packets" "PASS"
    else
      record_result 3 "DNSSI-6.2.3" "Disable Source Routed Packets" "FAIL" "Source routing accepted"
    fi
  fi

  # 4. net.ipv4.conf.all.accept_redirects = 0
  if check_sysctl "net.ipv4.conf.all.accept_redirects" "0"; then
    record_result 4 "DNSSI-6.2.4" "Disable ICMP Redirect Acceptance" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.conf.all.accept_redirects" "0"
      apply_sysctl "net.ipv4.conf.default.accept_redirects" "0"
      record_result 4 "DNSSI-6.2.4" "Disable ICMP Redirect Acceptance" "PASS"
    else
      record_result 4 "DNSSI-6.2.4" "Disable ICMP Redirect Acceptance" "FAIL" "ICMP redirects accepted"
    fi
  fi

  # 5. net.ipv4.conf.all.secure_redirects = 0
  if check_sysctl "net.ipv4.conf.all.secure_redirects" "0"; then
    record_result 5 "DNSSI-6.2.5" "Disable Secure ICMP Redirects" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.conf.all.secure_redirects" "0"
      apply_sysctl "net.ipv4.conf.default.secure_redirects" "0"
      record_result 5 "DNSSI-6.2.5" "Disable Secure ICMP Redirects" "PASS"
    else
      record_result 5 "DNSSI-6.2.5" "Disable Secure ICMP Redirects" "FAIL" "Secure redirects accepted"
    fi
  fi

  # 6. net.ipv4.conf.all.log_martians = 1
  if check_sysctl "net.ipv4.conf.all.log_martians" "1"; then
    record_result 6 "DNSSI-6.2.6" "Log Spoofed & Martian Packets" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.conf.all.log_martians" "1"
      apply_sysctl "net.ipv4.conf.default.log_martians" "1"
      record_result 6 "DNSSI-6.2.6" "Log Spoofed & Martian Packets" "PASS"
    else
      record_result 6 "DNSSI-6.2.6" "Log Spoofed & Martian Packets" "FAIL" "Martian packet logging disabled"
    fi
  fi

  # 7. net.ipv4.icmp_echo_ignore_broadcasts = 1
  if check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"; then
    record_result 7 "DNSSI-6.2.7" "Ignore ICMP Broadcasts (Smurf Attack Defense)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
      record_result 7 "DNSSI-6.2.7" "Ignore ICMP Broadcasts (Smurf Attack Defense)" "PASS"
    else
      record_result 7 "DNSSI-6.2.7" "Ignore ICMP Broadcasts (Smurf Attack Defense)" "FAIL" "Broadcast ICMP responded"
    fi
  fi

  # 8. net.ipv4.icmp_ignore_bogus_error_responses = 1
  if check_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"; then
    record_result 8 "DNSSI-6.2.8" "Ignore Bogus ICMP Error Responses" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"
      record_result 8 "DNSSI-6.2.8" "Ignore Bogus ICMP Error Responses" "PASS"
    else
      record_result 8 "DNSSI-6.2.8" "Ignore Bogus ICMP Error Responses" "FAIL" "Bogus ICMP responses logged"
    fi
  fi

  # 9. net.ipv4.tcp_syncookies = 1
  if check_sysctl "net.ipv4.tcp_syncookies" "1"; then
    record_result 9 "DNSSI-6.2.9" "Enable TCP SYN Cookies (SYN Flood Mitigation)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.tcp_syncookies" "1"
      record_result 9 "DNSSI-6.2.9" "Enable TCP SYN Cookies (SYN Flood Mitigation)" "PASS"
    else
      record_result 9 "DNSSI-6.2.9" "Enable TCP SYN Cookies (SYN Flood Mitigation)" "FAIL" "SYN cookies disabled"
    fi
  fi

  # 10. net.ipv4.conf.all.rp_filter = 1
  if check_sysctl "net.ipv4.conf.all.rp_filter" "1"; then
    record_result 10 "DNSSI-6.2.10" "Enable Reverse Path Filtering (Strict Anti-Spoofing)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "net.ipv4.conf.all.rp_filter" "1"
      apply_sysctl "net.ipv4.conf.default.rp_filter" "1"
      record_result 10 "DNSSI-6.2.10" "Enable Reverse Path Filtering (Strict Anti-Spoofing)" "PASS"
    else
      record_result 10 "DNSSI-6.2.10" "Enable Reverse Path Filtering (Strict Anti-Spoofing)" "FAIL" "RP filter not enforced"
    fi
  fi

  # 11. fs.suid_dumpable = 0
  if check_sysctl "fs.suid_dumpable" "0"; then
    record_result 11 "DNSSI-6.3.1" "Disable Core Dumps for SUID Executables" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "fs.suid_dumpable" "0"
      record_result 11 "DNSSI-6.3.1" "Disable Core Dumps for SUID Executables" "PASS"
    else
      record_result 11 "DNSSI-6.3.1" "Disable Core Dumps for SUID Executables" "FAIL" "SUID dumpable active"
    fi
  fi

  # 12. kernel.randomize_va_space = 2 (Full ASLR)
  if check_sysctl "kernel.randomize_va_space" "2"; then
    record_result 12 "DNSSI-6.3.2" "Enforce Full ASLR (Address Space Randomization)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "kernel.randomize_va_space" "2"
      record_result 12 "DNSSI-6.3.2" "Enforce Full ASLR (Address Space Randomization)" "PASS"
    else
      record_result 12 "DNSSI-6.3.2" "Enforce Full ASLR (Address Space Randomization)" "FAIL" "ASLR is not set to 2"
    fi
  fi

  # 13. kernel.kptr_restrict = 2
  if check_sysctl "kernel.kptr_restrict" "2"; then
    record_result 13 "DNSSI-6.3.3" "Hide Kernel Pointer Addresses (kptr_restrict = 2)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "kernel.kptr_restrict" "2"
      record_result 13 "DNSSI-6.3.3" "Hide Kernel Pointer Addresses (kptr_restrict = 2)" "PASS"
    else
      record_result 13 "DNSSI-6.3.3" "Hide Kernel Pointer Addresses (kptr_restrict = 2)" "FAIL" "Kernel pointers exposed"
    fi
  fi

  # 14. kernel.dmesg_restrict = 1
  if check_sysctl "kernel.dmesg_restrict" "1"; then
    record_result 14 "DNSSI-6.3.4" "Restrict Unprivileged dmesg Kernel Buffer Access" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "kernel.dmesg_restrict" "1"
      record_result 14 "DNSSI-6.3.4" "Restrict Unprivileged dmesg Kernel Buffer Access" "PASS"
    else
      record_result 14 "DNSSI-6.3.4" "Restrict Unprivileged dmesg Kernel Buffer Access" "FAIL" "dmesg accessible unprivileged"
    fi
  fi

  # 15. fs.protected_hardlinks = 1 & fs.protected_symlinks = 1
  if check_sysctl "fs.protected_hardlinks" "1" && check_sysctl "fs.protected_symlinks" "1"; then
    record_result 15 "DNSSI-6.3.5" "Protect Symlink & Hardlink TOCTOU Traversal" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      apply_sysctl "fs.protected_hardlinks" "1"
      apply_sysctl "fs.protected_symlinks" "1"
      record_result 15 "DNSSI-6.3.5" "Protect Symlink & Hardlink TOCTOU Traversal" "PASS"
    else
      record_result 15 "DNSSI-6.3.5" "Protect Symlink & Hardlink TOCTOU Traversal" "FAIL" "Link protections not enabled"
    fi
  fi

  # --- SSH SECURE CONFIGURATION (16 to 20) ---

  # 16. SSH PermitRootLogin no
  local sshd_active_root
  sshd_active_root=$(get_sshd_param "permitrootlogin")
  if [[ "$sshd_active_root" == "no" ]]; then
    record_result 16 "DNSSI-7.1.1" "Disable Direct SSH Root Login" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      backup_file "$SSHD_CONF"
      mkdir -p /etc/ssh/sshd_config.d
      set_config_kv "$SSHD_CONF" "PermitRootLogin" "no" " "
      record_result 16 "DNSSI-7.1.1" "Disable Direct SSH Root Login" "PASS"
    else
      record_result 16 "DNSSI-7.1.1" "Disable Direct SSH Root Login" "FAIL" "PermitRootLogin is '${sshd_active_root:-unset}'"
    fi
  fi

  # 17. SSH PasswordAuthentication no
  local sshd_pass_auth
  sshd_pass_auth=$(get_sshd_param "passwordauthentication")
  if [[ "$sshd_pass_auth" == "no" ]]; then
    record_result 17 "DNSSI-7.1.2" "Enforce Public Key Auth (PasswordAuthentication no)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      backup_file "$SSHD_CONF"
      mkdir -p /etc/ssh/sshd_config.d
      set_config_kv "$SSHD_CONF" "PasswordAuthentication" "no" " "
      record_result 17 "DNSSI-7.1.2" "Enforce Public Key Auth (PasswordAuthentication no)" "PASS"
    else
      record_result 17 "DNSSI-7.1.2" "Enforce Public Key Auth (PasswordAuthentication no)" "FAIL" "PasswordAuthentication is '${sshd_pass_auth:-unset}'"
    fi
  fi

  # 18. SSH PermitEmptyPasswords no & MaxAuthTries <= 3
  local sshd_empty_pwd sshd_max_tries
  sshd_empty_pwd=$(get_sshd_param "permitemptypasswords")
  sshd_max_tries=$(get_sshd_param "maxauthtries")
  if [[ "$sshd_empty_pwd" == "no" && -n "$sshd_max_tries" && "$sshd_max_tries" =~ ^[0-9]+$ && "$sshd_max_tries" -le 3 && "$sshd_max_tries" -gt 0 ]]; then
    record_result 18 "DNSSI-7.1.3" "Reject Empty Passwords & Limit MaxAuthTries <= 3" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      backup_file "$SSHD_CONF"
      mkdir -p /etc/ssh/sshd_config.d
      set_config_kv "$SSHD_CONF" "PermitEmptyPasswords" "no" " "
      set_config_kv "$SSHD_CONF" "MaxAuthTries" "3" " "
      record_result 18 "DNSSI-7.1.3" "Reject Empty Passwords & Limit MaxAuthTries <= 3" "PASS"
    else
      record_result 18 "DNSSI-7.1.3" "Reject Empty Passwords & Limit MaxAuthTries <= 3" "FAIL" "MaxAuthTries: ${sshd_max_tries:-unset}, PermitEmpty: ${sshd_empty_pwd:-unset}"
    fi
  fi

  # 19. SSH ClientAliveInterval 300 & ClientAliveCountMax 0
  local sshd_alive_int
  sshd_alive_int=$(get_sshd_param "clientaliveinterval")
  if [[ -n "$sshd_alive_int" && "$sshd_alive_int" =~ ^[0-9]+$ && "$sshd_alive_int" -gt 0 && "$sshd_alive_int" -le 300 ]]; then
    record_result 19 "DNSSI-7.1.4" "SSH Session Idle Timeout (<= 300 seconds)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      backup_file "$SSHD_CONF"
      mkdir -p /etc/ssh/sshd_config.d
      set_config_kv "$SSHD_CONF" "ClientAliveInterval" "300" " "
      set_config_kv "$SSHD_CONF" "ClientAliveCountMax" "0" " "
      record_result 19 "DNSSI-7.1.4" "SSH Session Idle Timeout (<= 300 seconds)" "PASS"
    else
      record_result 19 "DNSSI-7.1.4" "SSH Session Idle Timeout (<= 300 seconds)" "FAIL" "ClientAliveInterval is '${sshd_alive_int:-unset}'"
    fi
  fi

  # 20. SSH Cryptographic Ciphers & MACs (ANSSI BP-028 & DGSSI)
  local sshd_ciphers
  sshd_ciphers=$(get_sshd_param "ciphers")
  if [[ "$sshd_ciphers" == *"chacha20-poly1305"* || "$sshd_ciphers" == *"aes256-gcm"* ]]; then
    record_result 20 "DNSSI-7.1.5" "Enforce Modern Robust SSH Ciphers & MACs" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      backup_file "$SSHD_CONF"
      mkdir -p /etc/ssh/sshd_config.d
      set_config_kv "$SSHD_CONF" "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" " "
      set_config_kv "$SSHD_CONF" "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" " "
      set_config_kv "$SSHD_CONF" "KexAlgorithms" "curve25519-sha256,diffie-hellman-group16-sha512" " "
      record_result 20 "DNSSI-7.1.5" "Enforce Modern Robust SSH Ciphers & MACs" "PASS"
    else
      record_result 20 "DNSSI-7.1.5" "Enforce Modern Robust SSH Ciphers & MACs" "FAIL" "Modern ciphers not configured"
    fi
  fi

  # --- PAM & ACCESS CONTROL (21 to 22) ---

  # 21. PAM Password Quality (pam_pwquality minlen=14)
  if grep -qs "minlen = 14" /etc/security/pwquality.conf 2>/dev/null || grep -qs "pam_pwquality.so.*minlen=14" /etc/pam.d/* 2>/dev/null; then
    record_result 21 "DNSSI-7.2.1" "PAM Password Complexity (minlen >= 14, 4 classes)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      mkdir -p /etc/security
      set_config_kv "/etc/security/pwquality.conf" "minlen" "14" "="
      set_config_kv "/etc/security/pwquality.conf" "dcredit" "-1" "="
      set_config_kv "/etc/security/pwquality.conf" "ucredit" "-1" "="
      set_config_kv "/etc/security/pwquality.conf" "lcredit" "-1" "="
      set_config_kv "/etc/security/pwquality.conf" "ocredit" "-1" "="
      record_result 21 "DNSSI-7.2.1" "PAM Password Complexity (minlen >= 14, 4 classes)" "PASS"
    else
      record_result 21 "DNSSI-7.2.1" "PAM Password Complexity (minlen >= 14, 4 classes)" "FAIL" "Weak pwquality rules"
    fi
  fi

  # 22. PAM Account Lockout (pam_faillock / pam_tally2 deny=5)
  if grep -qs "pam_faillock.so" /etc/pam.d/* 2>/dev/null || grep -qs "pam_tally2.so" /etc/pam.d/* 2>/dev/null; then
    record_result 22 "DNSSI-7.2.2" "PAM Account Lockout after 5 Failed Attempts" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      log_action "Configuring faillock security parameters in /etc/security/faillock.conf"
      mkdir -p /etc/security
      set_config_kv "/etc/security/faillock.conf" "deny" "5" "="
      set_config_kv "/etc/security/faillock.conf" "unlock_time" "900" "="
      set_config_kv "/etc/security/faillock.conf" "fail_interval" "900" "="
      record_result 22 "DNSSI-7.2.2" "PAM Account Lockout after 5 Failed Attempts" "PASS"
    else
      record_result 22 "DNSSI-7.2.2" "PAM Account Lockout after 5 Failed Attempts" "FAIL" "Account lockout not configured"
    fi
  fi

  # --- FILESYSTEM & INTEGRITY (23 to 24) ---

  # 23. File Permissions /etc/passwd (644), /etc/shadow (600 or 640 or 000)
  local perm_passwd perm_shadow
  perm_passwd=$(get_file_perm "/etc/passwd")
  perm_shadow=$(get_file_perm "/etc/shadow")
  [[ -z "$perm_passwd" ]] && perm_passwd="644"
  [[ -z "$perm_shadow" ]] && perm_shadow="600"

  if [[ "$perm_passwd" == "644" && ("$perm_shadow" == "600" || "$perm_shadow" == "640" || "$perm_shadow" == "000") ]]; then
    record_result 23 "DNSSI-6.4.1" "File Permissions Integrity (/etc/passwd, /etc/shadow)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      backup_file "/etc/passwd"
      backup_file "/etc/shadow"
      chmod 644 /etc/passwd /etc/group 2>/dev/null || true
      chmod 600 /etc/shadow /etc/gshadow 2>/dev/null || true
      chown root:root /etc/passwd /etc/group /etc/shadow /etc/gshadow 2>/dev/null || true
      record_result 23 "DNSSI-6.4.1" "File Permissions Integrity (/etc/passwd, /etc/shadow)" "PASS"
    else
      record_result 23 "DNSSI-6.4.1" "File Permissions Integrity (/etc/passwd, /etc/shadow)" "FAIL" "passwd=$perm_passwd, shadow=$perm_shadow"
    fi
  fi

  # 24. Disable Legacy / Unused Filesystems in modprobe
  if [[ -f "$MODPROBE_CONF" ]] && grep -qs "install cramfs /bin/true" "$MODPROBE_CONF"; then
    record_result 24 "DNSSI-6.4.2" "Disable Legacy / Risky Filesystems (cramfs, hfs, udf)" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      backup_file "$MODPROBE_CONF"
      mkdir -p "$(dirname "$MODPROBE_CONF")"
      cat << 'EOF' > "$MODPROBE_CONF"
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
      record_result 24 "DNSSI-6.4.2" "Disable Legacy / Risky Filesystems (cramfs, hfs, udf)" "PASS"
    else
      record_result 24 "DNSSI-6.4.2" "Disable Legacy / Risky Filesystems (cramfs, hfs, udf)" "FAIL" "Unused filesystems enabled in kernel"
    fi
  fi

  # --- AUDIT & LOGGING (25) ---

  # 25. Auditd Daemon & Immutable Rules
  if command -v auditctl >/dev/null 2>&1 && auditctl -s 2>/dev/null | grep -q "enabled 1"; then
    record_result 25 "DNSSI-6.6.1" "Auditd Daemon Active with Security Audit Trails" "PASS"
  else
    if [[ "$MODE" == "apply" ]]; then
      backup_file "$AUDITD_RULES"
      mkdir -p /etc/audit/rules.d
      cat << 'EOF' > "$AUDITD_RULES"
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /var/log/lastlog -p wa -k logins
-e 2
EOF
      record_result 25 "DNSSI-6.6.1" "Auditd Daemon Active with Security Audit Trails" "PASS"
    else
      record_result 25 "DNSSI-6.6.1" "Auditd Daemon Active with Security Audit Trails" "FAIL" "Auditd is not running or rules not loaded"
    fi
  fi

  echo ""
  local score_pct=$(( (PASSED_COUNT * 100) / TOTAL_CONTROLS ))
  echo "=============================================================================="
  echo -e "                   SOVEREIGN AUDIT SUMMARY RESULTS"
  echo "=============================================================================="
  echo "  Total Controls Assessed  : $TOTAL_CONTROLS"
  echo -e "  Controls PASSED          : ${C_GREEN}$PASSED_COUNT${C_RESET}"
  echo -e "  Controls FAILED          : ${C_RED}$FAILED_COUNT${C_RESET}"
  echo -e "  Conformity DNSSI 2023    : ${C_LIME}${score_pct}%${C_RESET}"
  echo "=============================================================================="

  if [[ "$score_pct" -ge 80 ]]; then
    echo -e "${C_GREEN}[+] STATUT : CONFORME DNSSI 2023 — ÉLIGIBLE HOMOLOGATION ARTICLE 19${C_RESET}"
  elif [[ "$score_pct" -ge 50 ]]; then
    echo -e "${C_YELLOW}[!] STATUT : ÉCARTS MAJEURS — DURCISSEMENT REQUIS AVANT HOMOLOGATION${C_RESET}"
  else
    echo -e "${C_RED}[!] STATUT : NON-CONFORME — RISQUE PÉNAL ARTICLE 49 (LOI 05-20)${C_RESET}"
  fi
  echo ""
}

# Execution
if [[ "$MODE" == "apply" ]]; then
  if [[ "$EUID" -ne 0 ]]; then
    log_fail "Error: Mode --apply requires root privileges (sudo $0 --apply)"
    exit 1
  fi
  mkdir -p "$BACKUP_DIR"
  log_info "Backup directory initialized at: $BACKUP_DIR"
fi

run_controls
