#!/bin/bash
# RHEL health check (7~8 base)

########################
# 기본 설정
########################

REPORT_DIR="./reports"

# 네트워크 점검 대상
PING_TARGETS=("8.8.8.8" "1.1.1.1")
TCP_TARGETS=("127.0.0.1:22")  # "호스트:포트" 형식

# 체크할 systemd 서비스
SERVICES=("sshd" "crond")

# 로그 파일 및 tail 라인 수
LOG_FILES=("/var/log/messages" "/var/log/secure")
LOG_TAIL_LINES=200

# 임계값
CPU_WARN=70
CPU_CRIT=90
MEM_WARN=75
MEM_CRIT=90
DISK_WARN=80
DISK_CRIT=90

########################
# 내부 상태 변수 (요약용)
########################

CPU_STATUS="UNKNOWN"
MEM_STATUS="UNKNOWN"
DISK_CRIT_COUNT=0
DISK_WARN_COUNT=0
INODE_CRIT_COUNT=0
INODE_WARN_COUNT=0
PING_FAIL_COUNT=0
TCP_FAIL_COUNT=0
SERVICE_FAIL_COUNT=0

REPORT_FILE=""

########################
# 공통 유틸
########################

ensure_report_dir() {
  mkdir -p "$REPORT_DIR"
}

append() {
  # 리포트 파일에 한 줄 추가
  echo "$@" >> "$REPORT_FILE"
}

append_header() {
  local title="$1"
  append ""
  append "========== $title =========="
  append ""
}

########################
# OS 체크 (리눅스 전용)
########################

check_os() {
  local os
  os=$(uname -s 2>/dev/null || echo "UNKNOWN")
  if [ "$os" != "Linux" ]; then
    echo "이 스크립트는 RHEL 7~8 리눅스 서버에서 실행하도록 설계되었습니다. (현재 OS: $os)"
    exit 1
  fi
}

########################
# 시스템 정보
########################

check_system_info() {
  append_header "SYSTEM"

  local hostname os kernel boot_time uptime load

  hostname=$(hostname 2>/dev/null)
  os=$(cat /etc/redhat-release 2>/dev/null || uname -r)
  kernel=$(uname -r 2>/dev/null)

  # uptime/boot time
  if command -v who >/dev/null 2>&1; then
    boot_time=$(who -b 2>/dev/null | awk '{print $3" "$4}')
  else
    boot_time="unknown"
  fi

  if command -v uptime >/dev/null 2>&1; then
    uptime=$(uptime -p 2>/dev/null)
  else
    uptime="unknown"
  fi

  # load average
  if command -v uptime >/dev/null 2>&1; then
    load=$(uptime 2>/dev/null | sed 's/.*load average: //')
  else
    load="unknown"
  fi

  append "Hostname   : $hostname"
  append "OS         : $os"
  append "Kernel     : $kernel"
  append "Boot Time  : $boot_time"
  append "Uptime     : $uptime"
  append "Load Avg   : $load"
}

########################
# CPU
########################

get_cpu_usage() {
  # mpstat가 있으면 사용, 없으면 top 결과 활용
  if command -v mpstat >/dev/null 2>&1; then
    mpstat 1 1 | awk '/Average:/ && ($2 ~ /all/ || $3 ~ /all/) {print 100-$NF}'
  else
    LANG=C top -bn1 | awk '/Cpu\(s\)/ {print 100-$8}' | head -n1
  fi
}

check_cpu() {
  append_header "CPU"

  local usage_int usage status

  usage=$(get_cpu_usage | tr -d '[:space:]')
  if [ -z "$usage" ]; then
    usage_int=0
  else
    usage_int=${usage%.*}
  fi

  status="OK"
  if [ "$usage_int" -ge "$CPU_CRIT" ]; then
    status="CRIT"
  elif [ "$usage_int" -ge "$CPU_WARN" ]; then
    status="WARN"
  fi
  CPU_STATUS="$status"

  append "CPU Usage : ${usage_int}% (Status: $status)"
  append "Top CPU Processes (PID CMD %CPU):"

  LANG=C ps -eo pid,comm,%cpu --sort=-%cpu | head -n 6 | while read -r line; do
    append "  $line"
  done
}

########################
# 메모리
########################

check_memory() {
  append_header "MEMORY"

  local total used percent swap_total swap_used swap_percent status

  if command -v free >/dev/null 2>&1; then
    # free -m 결과에서 Mem: 라인 파싱
    read _ total used _ <<<"$(free -m | awk '/^Mem:/ {print $2" "$3" "$4}')"
    percent=$(awk "BEGIN {if ($total>0) printf \"%d\", ($used/$total)*100; else print 0}")
    # swap
    read _ swap_total swap_used _ <<<"$(free -m | awk '/^Swap:/ {print $2" "$3" "$4}')"
    swap_percent=$(awk "BEGIN {if ($swap_total>0) printf \"%d\", ($swap_used/$swap_total)*100; else print 0}")
  else
    total=0; used=0; percent=0; swap_total=0; swap_used=0; swap_percent=0
  fi

  status="OK"
  if [ "$percent" -ge "$MEM_CRIT" ]; then
    status="CRIT"
  elif [ "$percent" -ge "$MEM_WARN" ]; then
    status="WARN"
  fi
  MEM_STATUS="$status"

  append "Mem Usage  : ${percent}% (Status: $status)  Total=${total}MB, Used=${used}MB"
  append "Swap Usage : ${swap_percent}%  Total=${swap_total}MB, Used=${swap_used}MB"
}

########################
# 디스크 용량
########################

check_disks() {
  append_header "DISKS"

  # -P: POSIX 포맷, LANG=C로 영문 강제
  LANG=C df -P | awk 'NR>1 {print $1" "$6" "$2" "$3" "$4" "$5}' | while read -r dev mnt total used avail perc; do
    # perc: "85%" 형태 → 숫자만
    local p status
    p=${perc%%%}
    status="OK"
    if [ "$p" -ge "$DISK_CRIT" ]; then
      status="CRIT"
      DISK_CRIT_COUNT=$((DISK_CRIT_COUNT+1))
    elif [ "$p" -ge "$DISK_WARN" ]; then
      status="WARN"
      DISK_WARN_COUNT=$((DISK_WARN_COUNT+1))
    fi
    append "$dev ($mnt): ${p}% used (Status: $status) Total=${total}K, Used=${used}K, Avail=${avail}K"
  done
}

########################
# inode 사용률
########################

check_inodes() {
  append_header "INODES"

  LANG=C df -Pi | awk 'NR>1 {print $1" "$6" "$2" "$3" "$4" "$5}' | while read -r dev mnt itotal iused ifree iperc; do
    local p status
    p=${iperc%%%}
    status="OK"
    if [ "$p" -ge "$DISK_CRIT" ]; then
      status="CRIT"
      INODE_CRIT_COUNT=$((INODE_CRIT_COUNT+1))
    elif [ "$p" -ge "$DISK_WARN" ]; then
      status="WARN"
      INODE_WARN_COUNT=$((INODE_WARN_COUNT+1))
    fi
    append "$dev ($mnt): ${p}% inode used (Status: $status) Total=${itotal}, Used=${iused}, Free=${ifree}"
  done
}

########################
# 네트워크 (PING/TCP)
########################

check_network() {
  append_header "NETWORK - PING"

  local host
  for host in "${PING_TARGETS[@]}"; do
    if ping -c 2 -W 1 "$host" >/dev/null 2>&1; then
      append "$host : OK"
    else
      append "$host : FAIL"
      PING_FAIL_COUNT=$((PING_FAIL_COUNT+1))
    fi
  done

  append_header "NETWORK - TCP"

  local entry h p
  for entry in "${TCP_TARGETS[@]}"; do
    h=${entry%%:*}
    p=${entry##*:}
    # /dev/tcp 사용 (bash 내장)
    if timeout 2 bash -c ">/dev/tcp/$h/$p" 2>/dev/null; then
      append "$h:$p : OK (connected)"
    else
      append "$h:$p : FAIL (cannot connect)"
      TCP_FAIL_COUNT=$((TCP_FAIL_COUNT+1))
    fi
  done
}

########################
# 서비스 상태 (systemd)
########################

check_services() {
  append_header "SERVICES"

  local svc status_raw
  for svc in "${SERVICES[@]}"; do
    if command -v systemctl >/dev/null 2>&1; then
      status_raw=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
      if [ "$status_raw" = "active" ]; then
        append "$svc : OK (systemd: $status_raw)"
      else
        append "$svc : FAIL (systemd: $status_raw)"
        SERVICE_FAIL_COUNT=$((SERVICE_FAIL_COUNT+1))
      fi
    else
      append "$svc : UNKNOWN (systemctl not found)"
    fi
  done
}

########################
# 로그 요약
########################

check_logs() {
  append_header "LOG SUMMARY (tail)"

  local file lines matches
  for file in "${LOG_FILES[@]}"; do
    if [ -r "$file" ]; then
      # tail 후 error|failed|critical 카운트
      lines=$(tail -n "$LOG_TAIL_LINES" "$file" 2>/dev/null | wc -l)
      matches=$(tail -n "$LOG_TAIL_LINES" "$file" 2>/dev/null | \
        grep -iE 'error|failed|critical' | wc -l)
      append "$file : tail ${lines} lines, matches=${matches}"
    else
      append "$file : 접근 불가(없음 또는 권한 부족)"
    fi
  done
}

########################
# 메인 리포트 생성
########################

generate_report() {
  ensure_report_dir
  REPORT_FILE="${REPORT_DIR}/infra_healthcheck_$(date +%Y%m%d_%H%M%S).txt"

  : > "$REPORT_FILE"  # 파일 초기화

  check_system_info
  check_cpu
  check_memory
  check_disks
  check_inodes
  check_network
  check_services
  check_logs
}

########################
# main
########################

main() {
  check_os

  echo "infra-healthcheck: Linux 서버 점검을 시작합니다..."
  generate_report
  echo "리포트 생성 완료: $REPORT_FILE"

  echo
  echo "[요약]"
  echo "- CPU 사용률      : Status = ${CPU_STATUS}"
  echo "- 메모리 사용률   : Status = ${MEM_STATUS}"
  echo "- 디스크 CRIT/WARN: ${DISK_CRIT_COUNT}/${DISK_WARN_COUNT}"
  echo "- inode CRIT/WARN : ${INODE_CRIT_COUNT}/${INODE_WARN_COUNT}"
  echo "- PING 실패 대상  : ${PING_FAIL_COUNT}"
  echo "- TCP 실패 대상   : ${TCP_FAIL_COUNT}"
  echo "- 서비스 비정상   : ${SERVICE_FAIL_COUNT}"
  echo
  echo "자세한 내용은 리포트 파일을 확인하세요."
}

main "$@"
