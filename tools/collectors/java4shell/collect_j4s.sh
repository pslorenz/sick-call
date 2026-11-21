#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
# collect_j4s.sh - Java4Shell (CVE-2026-114938) precondition collector for Linux.
# Read-only. Finds every Java runtime on the host (bundled ones too), asks each JVM
# what it would do on this CPU, and checks running JVMs for workaround flags.
# Output: CSV on stdout, one row per java binary. Feed it to j4s_triage.py.
#
# Usage: sudo ./collect_j4s.sh [--include-container-layers] > "$(hostname)-j4s.csv"
# Run as root so /proc/<pid>/environ is readable for service JVMs.

set -u
INCLUDE_LAYERS=0
[ "${1:-}" = "--include-container-layers" ] && INCLUDE_LAYERS=1

host=$(hostname -f 2>/dev/null || hostname)
arch=$(uname -m)
cpu_model=$(grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//; s/,/ /g')
flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2-)
vbmi=no
if [ "$arch" = "x86_64" ]; then
  have=0
  for f in avx512f avx512bw avx512vbmi bmi2; do
    echo " $flags " | grep -q " $f " && have=$((have+1))
  done
  [ "$have" -eq 4 ] && vbmi=yes
fi

prune='-path /proc -o -path /sys -o -path /dev -o -path /run'
[ "$INCLUDE_LAYERS" -eq 0 ] && prune="$prune -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/containers"

# Mitigation flags we look for in live processes (command line or env).
mit_re='UseBASE64Intrinsics|UseAVX=[0-2]([^0-9]|$)|DisableIntrinsic=[^ ]*_base64_decodeBlock'

echo "host,os,arch,cpu_model,vbmi,java_path,java_version,runtime_version,java_vendor,use_avx,base64_intrinsics,running_pids,live_mitigation,collected_utc"

# shellcheck disable=SC2086
find / \( $prune \) -prune -o -type f -name java -perm -u+x -print 2>/dev/null | sort -u | while read -r j; do
  real=$(readlink -f "$j")
  # Probe with a clean environment so the result reflects the JVM default, not this shell.
  props=$(env -u _JAVA_OPTIONS -u JAVA_TOOL_OPTIONS -u JDK_JAVA_OPTIONS timeout 20 "$real" -XshowSettings:properties -version 2>&1)
  ver=$(echo "$props" | awk -F' = ' '/^ *java.version = /{print $2; exit}')
  rver=$(echo "$props" | awk -F' = ' '/^ *java.runtime.version = /{print $2; exit}')
  vendor=$(echo "$props" | awk -F' = ' '/^ *java.vendor = /{print $2; exit}' | sed 's/,/ /g')
  [ -z "$ver" ] && continue   # not a working JVM (wrapper script, wrong arch, etc.)
  pff=$(env -u _JAVA_OPTIONS -u JAVA_TOOL_OPTIONS -u JDK_JAVA_OPTIONS timeout 20 "$real" -XX:+PrintFlagsFinal -version 2>/dev/null)
  avx=$(echo "$pff" | awk '$2=="UseAVX"{print $4; exit}')
  b64=$(echo "$pff" | awk '$2=="UseBASE64Intrinsics"{print $4; exit}')

  pids=""; mit=no
  for p in /proc/[0-9]*; do
    exe=$(readlink -f "$p/exe" 2>/dev/null) || continue
    [ "$exe" = "$real" ] || continue
    pid=${p#/proc/}
    pids="$pids $pid"
    live=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null; tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -E '^(_JAVA_OPTIONS|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS)=')
    echo "$live" | grep -Eq -- "$mit_re" && mit=yes
  done
  pids=$(echo "$pids" | sed 's/^ //; s/ /;/g')
  [ -z "$pids" ] && mit=n/a

  echo "$host,linux,$arch,$cpu_model,$vbmi,$real,$ver,$rver,$vendor,${avx:-?},${b64:-?},$pids,$mit,$(date -u +%FT%TZ)"
done
