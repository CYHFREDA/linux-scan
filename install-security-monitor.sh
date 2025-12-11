#!/bin/bash
set -e

# 在腳本開始時就切換到穩定目錄，避免後續操作導致目錄問題
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || SCRIPT_DIR="/root"
SCRIPT_NAME="$(basename "$0")"
cd /tmp 2>/dev/null || cd / 2>/dev/null || true

sudo yum remove snapd snapd-selinux snap-confine -y &&sudo yum -y update
#########################################
# Security Monitor v3.5  (Full + Telegram)
# - 輕量、不卡、全面安全 + 即時 Telegram 通知
#########################################

if [ -z "$BASH_VERSION" ]; then
    echo "請用 bash 執行此腳本，例如： sudo bash $0"
    exit 1
fi

SCRIPT_VERSION="3.5"
INSTALL_DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "==========================================="
echo "  安全監控系統 v${SCRIPT_VERSION}"
echo "  安裝時間: ${INSTALL_DATE}"
echo "==========================================="

#########################################
# 目錄結構
#########################################
mkdir -p /opt/security/{scripts,logs,reports,config,tmp}
mkdir -p /opt/security
chmod 700 /opt/security

#########################################
# 選擇是否啟用 Telegram
#########################################
sudo rm -rf /opt/security/config/telegram.conf
# 設定檔
sudo bash -c "cat > /opt/security/config/telegram.token<< 'EOFF'
# Telegram 設定
TG_BOT_TOKEN="7785897695:AAGJ-ShDBHhqBonmtJiOrTT_-x1E-ws4v60"
TG_CHAT_ID="-5043743231"
EOFF"

#########################################
# 共用 Telegram 發送腳本
#########################################
cat > /opt/security/scripts/send-telegram.sh << 'EOF'
#!/bin/bash
TOKEN_FILE="/opt/security/config/telegram.token"
if [ ! -f "$TOKEN_FILE" ]; then exit 0; fi
source "$TOKEN_FILE"

TEXT="$1"
curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
     -d chat_id="${TG_CHAT_ID}" \
     -d text="$TEXT" \
     -d parse_mode="HTML" >/dev/null 2>&1
EOF

chmod +x /opt/security/scripts/send-telegram.sh

#########################################
# 安裝必要工具
#########################################
echo "安裝必要系統套件..."
dnf install -y epel-release

dnf install -y \
    fail2ban fail2ban-systemd \
    curl jq audit aide rkhunter \
    clamav clamav-update clamav-server clamav-server-systemd \
    inotify-tools \
    sysstat logrotate psmisc lsof net-tools \
    gcc make glibc-static

dnf groupinstall "Development Tools" -y

#########################################
# ClamAV daemon
#########################################
echo "== 修復 ClamAV daemon 啟動問題 =="

# 建立 scan.conf（如果不存在）
[ ! -f /etc/clamd.d/scan.conf ] && cp /etc/clamd.d/clamd.conf /etc/clamd.d/scan.conf

# scan.conf 權限
chown root:root /etc/clamd.d/scan.conf
chmod 644 /etc/clamd.d/scan.conf

# 修正內容
sed -i 's/^Example/#Example/' /etc/clamd.d/scan.conf
sed -i 's/^Foreground yes/#Foreground yes/' /etc/clamd.d/scan.conf

# 加 TCP 支援
grep -q "^TCPSocket" /etc/clamd.d/scan.conf || {
    echo "TCPSocket 3310" >> /etc/clamd.d/scan.conf
    echo "TCPAddr 127.0.0.1" >> /etc/clamd.d/scan.conf
}

# 建立 LocalSocket
mkdir -p /var/run/clamd.scan
chown root:root /var/run/clamd.scan
rm -f /var/run/clamd.scan/clamd.sock

# 建立資料夾並正確授權給 clamav
mkdir -p /var/lib/clamav/tmp
chown -R 989:988 /var/lib/clamav
chmod 755 /var/lib/clamav
chmod 700 /var/lib/clamav/tmp

# 更新病毒庫（用 root 執行避免權限問題）
freshclam || true

# systemd override 讓 clamd@scan 用 root 執行
mkdir -p /etc/systemd/system/clamd@scan.service.d
cat > /etc/systemd/system/clamd@scan.service.d/override.conf << EOF
[Service]
User=root
Group=root
EOF

systemctl daemon-reload
systemctl enable --now clamd@scan.service

if systemctl is-active --quiet clamd@scan.service; then
    echo "ClamAV daemon 啟動成功！"
else
    echo "ClamAV 啟動失敗，請查看 systemctl status clamd@scan"
fi

######################################### 
# 安裝 chkrootkit
#########################################
sudo dnf config-manager --set-enabled crb
sudo dnf install chkrootkit -y || {
    echo "Chkrootkit 不存在，改用源碼編譯"

    sudo mkdir -p /opt/security/tools
    WORK_DIR="/opt/security/tools"
    cd "$WORK_DIR" || cd /tmp

    echo "下載 chkrootkit (GitHub Mirror)..."
    sudo curl -L -o chkrootkit.zip https://github.com/Magentron/chkrootkit/archive/refs/heads/master.zip

    echo "解壓縮..."
    sudo unzip -oq chkrootkit.zip
    cd chkrootkit-master || cd /tmp

    echo "編譯..."
    sudo make sense

    echo "建立可執行連結..."
    sudo ln -sf "$(pwd)/chkrootkit" /usr/local/bin/chkrootkit

    echo "chkrootkit 安裝完成！"
    
    # 切換回穩定目錄
    cd /tmp 2>/dev/null || cd / 2>/dev/null || true
}

#########################################
# 安裝 Lynis
#########################################
echo "下載 Lynis v3.1.6..."
WORK_DIR="/tmp"
cd "$WORK_DIR" || cd /tmp

curl -sL "https://cisofy.com/files/lynis-3.1.6.tar.gz" -o lynis.tar.gz

if file lynis.tar.gz | grep -q 'gzip compressed'; then
    tar xzf lynis.tar.gz
    DIR=$(tar tzf lynis.tar.gz | head -1 | cut -f1 -d"/")  # 取得解壓後的第一個目錄

    # 如果已存在 lynis 目錄，先刪除
    [ -d /opt/lynis ] && rm -rf /opt/lynis

    mv "$DIR" /opt/lynis
    rm -f lynis.tar.gz
    echo "✅ Lynis 安裝完成 (v3.1.6)"
else
    echo "❌ 下載的檔案不是 gzip 格式 — 可能網址錯誤或網路問題"
    rm -f lynis.tar.gz
fi

# 切換回穩定目錄
cd /tmp 2>/dev/null || cd / 2>/dev/null || true

#########################################
# 安裝 Maldet
#########################################
echo "安裝 Maldet..."
if [ ! -d /usr/local/maldetect ]; then
    WORK_DIR="/tmp"
    cd "$WORK_DIR" || cd /tmp
    
    curl -s https://www.rfxn.com/downloads/maldetect-current.tar.gz -o maldetect.tar.gz
    tar xzf maldetect.tar.gz
    
    # 找到解壓後的目錄
    MALDET_DIR=$(find . -maxdepth 1 -type d -name "maldetect-*" | head -1)
    if [ -n "$MALDET_DIR" ] && [ -d "$MALDET_DIR" ]; then
        cd "$MALDET_DIR" || cd /tmp
        bash install.sh
    fi
    
    # 切換回穩定目錄
    cd /tmp 2>/dev/null || cd / 2>/dev/null || true
fi

#########################################
# 更新 ClamAV
#########################################
freshclam || true

#########################################
# 建立監控腳本
#########################################

# ==== Reverse Shell Detector ====
cat > /opt/security/scripts/reverse-shell-detector.sh << 'EOF'
#!/bin/bash
LOG="/opt/security/logs/reverse-shell.log"

# 獲取所有網路連接
ALL_CONNS=$(ss -tunap 2>/dev/null || true)

# 排除正常的 SSH 連接（sshd）和本地連接
# 只檢測可疑的連接模式：
# 1. 使用 nc/ncat 的連接（可能是 reverse shell）
# 2. 使用 perl/python 連接到外部 IP（排除本地）
# 3. bash/sh 連接到非標準端口的外部 IP

SUSPICIOUS=$(echo "$ALL_CONNS" | grep -v "sshd" | grep -v "127.0.0.1" | grep -v "::1" | \
    grep -E "(nc |ncat |netcat )" || true)

# 檢測 perl/python 連接到外部 IP（排除本地和常見服務端口）
PERL_PYTHON=$(echo "$ALL_CONNS" | grep -v "sshd" | grep -v "127.0.0.1" | grep -v "::1" | \
    grep -E "(perl|python)" | grep -vE ":(22|80|443|3306|5432|6379|8080|8443) " || true)

# 檢測 bash/sh 連接到可疑的外部 IP 和端口
BASH_SUSPICIOUS=$(echo "$ALL_CONNS" | grep -v "sshd" | grep -v "127.0.0.1" | grep -v "::1" | \
    grep -E "(bash|sh)" | grep -vE ":(22|80|443|3306|5432|6379|8080|8443) " | \
    grep -vE "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\." || true)

# 合併所有可疑連接
OUTPUT=""
if [ -n "$SUSPICIOUS" ]; then
    OUTPUT="${OUTPUT}${SUSPICIOUS}\n"
fi
if [ -n "$PERL_PYTHON" ]; then
    OUTPUT="${OUTPUT}${PERL_PYTHON}\n"
fi
if [ -n "$BASH_SUSPICIOUS" ]; then
    OUTPUT="${OUTPUT}${BASH_SUSPICIOUS}\n"
fi

# 如果有可疑連接，記錄並發送通知
if [ -n "$OUTPUT" ]; then
    # 去重並格式化
    OUTPUT=$(echo -e "$OUTPUT" | sort -u | grep -v "^$")
    
    if [ -n "$OUTPUT" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Reverse Shell Detected:" >> "$LOG"
        echo "$OUTPUT" >> "$LOG"
        echo "---" >> "$LOG"
        
        # 限制輸出長度，避免訊息過長
        OUTPUT_SHORT=$(echo "$OUTPUT" | head -n 10)
        MSG="🔴 <b>Reverse Shell 偵測</b>%0A<pre>${OUTPUT_SHORT}</pre>"
        [ $(echo "$OUTPUT" | wc -l) -gt 10 ] && MSG="${MSG}%0A<i>（還有更多連接，請查看日誌）</i>"
        
        /opt/security/scripts/send-telegram.sh "$MSG"
    fi
fi
EOF

# ==== Process Monitor ====
cat > /opt/security/scripts/process-monitor.sh << 'EOF'
#!/bin/bash
LOG="/opt/security/logs/process-monitor.log"

ps aux --sort=-%cpu | head -n 5 > /opt/security/tmp/top.txt

while read -r line; do
    cpu=$(echo "$line" | awk '{print $3}')
    mem=$(echo "$line" | awk '{print $4}')
    cmd=$(echo "$line" | awk '{print $11}')

    if (( $(echo "$cpu > 70" | bc -l) )); then
        echo "$line" >> "$LOG"
        /opt/security/scripts/send-telegram.sh "⚠️ <b>High CPU Usage</b>%0A$cmd%0ACPU: $cpu%"
    fi
done < /opt/security/tmp/top.txt
EOF

# ==== Network Monitor ====
cat > /opt/security/scripts/network-monitor.sh << 'EOF'
#!/bin/bash
LOG_FILE="/opt/security/logs/network-monitor.log"
ALERT_THRESHOLD_PORTS=20
CHECK_INTERVAL=300

echo "[$(date)] Network Monitor Started (每 ${CHECK_INTERVAL}s 檢查)" >> "$LOG_FILE"

declare -A PORT_SCAN_COUNT
declare -A WARNED_IPS

while true; do
    # === Port Scan 偵測 ===
    netstat -ntu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | while read count ip; do
        # 跳過本機和 Docker 內網
        if [[ "$ip" =~ ^(127\.|0\.|::|172\.(1[6-9]|2[0-9]|3[0-1])\.|10\.|192\.168\.) ]]; then
            continue
        fi
        
        if [ "$count" -gt $ALERT_THRESHOLD_PORTS ] && [ ! -z "$ip" ]; then
            PORT_SCAN_COUNT[$ip]=$((PORT_SCAN_COUNT[$ip] + 1))
            
            # 只在第一次或每 5 次警告
            if [ ${PORT_SCAN_COUNT[$ip]} -eq 1 ] || [ $((PORT_SCAN_COUNT[$ip] % 5)) -eq 0 ]; then
                MSG="🚨 <b>Port Scan 偵測</b>%0AIP: $ip%0A連線數: $count%0A累計次數: ${PORT_SCAN_COUNT[$ip]}%0A主機: $(hostname)"
                /opt/security/scripts/send-telegram.sh "$MSG" "high"
                echo "[$(date)] Port scan from $ip ($count conns, total: ${PORT_SCAN_COUNT[$ip]})" >> "$LOG_FILE"
            fi
        fi
    done

    sleep $CHECK_INTERVAL
done
EOF

# ==== File Monitor ====
cat > /opt/security/scripts/file-monitor.sh << 'EOF'
#!/bin/bash
LOG_FILE="/opt/security/logs/file-monitor.log"
SENSITIVE_PATHS="/etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config"

echo "[$(date)] File Monitor Started" >> "$LOG_FILE"

# 只監控 modify（內容變更）和 delete（刪除）
# 移除 attrib（屬性變更）以減少誤報
inotifywait -m -e modify,delete,create,move $SENSITIVE_PATHS 2>/dev/null | while read path action file; do
    echo "[$(date)] ${path}${file} ($action)" >> "$LOG_FILE"
    /opt/security/scripts/send-telegram.sh "🔐 <b>敏感檔案變更!</b>%0A檔案: ${path}${file}%0A動作: $action%0A時間: $(date '+%H:%M:%S')%0A主機: $(hostname)"
done
EOF
chmod +x /opt/security/scripts/*.sh

#########################################
# systemd services
#########################################

declare -a SVC=("reverse-shell-detector" "process-monitor" "network-monitor" "file-monitor")

for svc in "${SVC[@]}"; do
cat > /etc/systemd/system/${svc}.service << EOF
[Unit]
Description=${svc}

[Service]
ExecStart=/bin/bash /opt/security/scripts/${svc}.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF
done

systemctl daemon-reload
systemctl enable --now reverse-shell-detector process-monitor network-monitor file-monitor

#########################################
# ===== 每日檢查腳本（整合 Lynis、chkrootkit、LMD） =====
#########################################
sudo tee /etc/cron.daily/security-check > /dev/null << 'EOFF'
#!/bin/bash
set -e

# ===== 暫停高 CPU 偵測 =====
systemctl stop process-monitor

REPORT_FILE="/opt/security/logs/daily-report-$(date +%Y%m%d).txt"
echo "=== Daily Security Report - $(date) ===" > "$REPORT_FILE"

# ===== Fail2ban 統計 =====
BANNED_COUNT=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo 0)
TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $4}' || echo 0)
echo "=== Fail2ban 封鎖統計 ===" >> "$REPORT_FILE"
fail2ban-client status sshd >> "$REPORT_FILE" 2>&1 || echo "Fail2ban 未啟動" >> "$REPORT_FILE"

# ===== Audit 事件摘要 =====
echo "=== 今日 Audit 事件摘要 ===" >> "$REPORT_FILE"
AUDIT_EVENTS=$(ausearch -ts today 2>/dev/null | grep -E 'passwd|sudoers|shadow|sshd_config' | wc -l || echo 0)
ausearch -ts today 2>/dev/null | grep -E 'passwd|sudoers|shadow|sshd_config' >> "$REPORT_FILE" 2>&1 || echo "無異常事件" >> "$REPORT_FILE"

# ===== 今日登入記錄 =====
echo "=== 今日登入記錄 ===" >> "$REPORT_FILE"
LOGIN_COUNT=$(last -F | grep "$(date +%a\ %b\ %e)" | wc -l || echo 0)
LOGIN_USERS=$(last -F | grep "$(date +%a\ %b\ %e)" | awk '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//' || echo "無")
last -F | grep "$(date +%a\ %b\ %e)" >> "$REPORT_FILE" 2>&1

# ===== 系統更新狀態 =====
echo "=== 系統更新狀態 (Security Updates) ===" >> "$REPORT_FILE"
SECURITY_UPDATES=$(dnf check-update --security 2>&1 | grep -c "^[a-zA-Z]" || echo 0)
dnf check-update --security >> "$REPORT_FILE" 2>&1 || echo "無可用更新" >> "$REPORT_FILE"

# ===== 磁碟使用狀態 =====
echo "=== 磁碟使用狀態 ===" >> "$REPORT_FILE"
DISK_USAGE=$(df -h / | tail -1 | awk '{print $5}' | tr -d '%')
df -h >> "$REPORT_FILE"

# ===== 記憶體使用狀態 =====
MEM_TOTAL=$(free -h | grep Mem | awk '{print $2}')
MEM_USED=$(free -h | grep Mem | awk '{print $3}')
MEM_PERCENT=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')

# ===== 重要服務運行狀態 =====
echo "=== 重要服務狀態 ===" >> "$REPORT_FILE"
FAILED_SERVICES=""
for svc in sshd nginx mysql docker; do
    if systemctl is-active --quiet $svc 2>/dev/null; then
        echo "$svc: 運行中" >> "$REPORT_FILE"
    else
        FAILED_SERVICES="$FAILED_SERVICES $svc"
        echo "$svc: 未啟動" >> "$REPORT_FILE"
    fi
done

# ===== 高 CPU / 記憶體使用進程 =====
echo "=== 高 CPU / 記憶體使用進程 (Top 5) ===" >> "$REPORT_FILE"
CPU_TOP=$(ps aux --sort=-%cpu | head -n 6 | tail -n 5)
MEM_TOP=$(ps aux --sort=-%mem | head -n 6 | tail -n 5)
echo "$CPU_TOP" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "$MEM_TOP" >> "$REPORT_FILE"

# 提取最高 CPU 使用率
MAX_CPU=$(ps aux --sort=-%cpu | head -n 2 | tail -n 1 | awk '{print $3}')
MAX_CPU_PROC=$(ps aux --sort=-%cpu | head -n 2 | tail -n 1 | awk '{print $11}')

# ===== 網路連線統計 =====
echo "=== 網路連線統計 (Top 5 IP) ===" >> "$REPORT_FILE"
NET_TOP=$(ss -tan | awk '{print $5}' | cut -d: -f1 | grep -v "^$" | sort | uniq -c | sort -nr | head -n 5)
echo "$NET_TOP" >> "$REPORT_FILE"

# 檢查是否有異常連線數
SUSPICIOUS_CONN=$(echo "$NET_TOP" | head -n 1 | awk '{if ($1 > 50) print $2}')

# ===== 重要檔案變動摘要 =====
echo "=== 重要檔案變動 (過去 1 天) ===" >> "$REPORT_FILE"
FILE_CHANGES_COUNT=$(find /etc $( [ -d /var/www ] && echo /var/www ) -type f -mtime -1 2>/dev/null | wc -l || echo 0)
FILE_CHANGES=$(find /etc $( [ -d /var/www ] && echo /var/www ) -type f -mtime -1 2>/dev/null | head -n 10)
if [ -z "$FILE_CHANGES" ]; then 
    FILE_CHANGES="無檔案變動"
else
    echo "$FILE_CHANGES" >> "$REPORT_FILE"
fi

# ===== 檢查敏感檔案變動 =====
SENSITIVE_CHANGES=$(find /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config -mtime -1 2>/dev/null || echo "")
SENSITIVE_COUNT=$(echo "$SENSITIVE_CHANGES" | grep -v "^$" | wc -l)

# ===== 日誌摘要 (secure) =====
echo "=== /var/log/secure 今日摘要 ===" >> "$REPORT_FILE"
FAILED_LOGIN=$(grep "$(date +%b\ %e)" /var/log/secure 2>/dev/null | grep -i "failed" | wc -l || echo 0)
grep "$(date +%b\ %e)" /var/log/secure >> "$REPORT_FILE" 2>&1 || echo "無事件" >> "$REPORT_FILE"

# ===== ClamAV 輕量掃描 =====
CLAMAV_DIRS=(/home /root /opt /var/www /srv/data /data /backup)
CLAMAV_LOG="/opt/security/logs/clamav-daily-$(date +%Y%m%d).log"

freshclam || true

INFECTED_COUNT=0
for dir in "${CLAMAV_DIRS[@]}"; do
    [ -d "$dir" ] || continue
    SCAN_RESULT=$(nice -n 19 ionice -c3 clamdscan --fdpass --multiscan --infected --quiet "$dir" 2>&1 || true)
    echo "$SCAN_RESULT" >> "$CLAMAV_LOG"
    INFECTED_COUNT=$((INFECTED_COUNT + $(echo "$SCAN_RESULT" | grep -c "FOUND" || echo 0)))
done

# ===== chkrootkit 掃描 =====
CHKROOTKIT_LOG="/opt/security/logs/chkrootkit-$(date +%Y%m%d).log"
chkrootkit > $CHKROOTKIT_LOG 2>&1
ROOTKIT_WARNINGS=$(grep -i "warning\|infected" $CHKROOTKIT_LOG | wc -l || echo 0)

# ===== LMD 掃描 =====
MALDET_LOG="/opt/security/logs/maldet-$(date +%Y%m%d).log"
maldet -a /home /var/www > $MALDET_LOG 2>&1 || true
MALWARE_FOUND=$(grep -i "malware detected" $MALDET_LOG | wc -l || echo 0)

# ===== Lynis 每週掃描 (週日) =====
LYNIS_MSG=""
if [ $(date +%u) -eq 7 ]; then
    LYNIS_LOG="/opt/security/logs/lynis-$(date +%Y%m%d).log"
    /opt/lynis/lynis audit system --quiet > $LYNIS_LOG
    WARNINGS=$(grep 'Warning:' $LYNIS_LOG | wc -l)
    SUGGESTIONS=$(grep 'Suggestion:' $LYNIS_LOG | wc -l)
    LYNIS_MSG="%0A%0A🛠 <b>Lynis 系統檢查</b>%0A警告: $WARNINGS | 建議: $SUGGESTIONS"
fi

# ===== 構建智能 Telegram 訊息 =====
MSG="📊 <b>每日安全報告</b> - $(date +%m/%d)%0A━━━━━━━━━━━━━━━━"
MSG="$MSG%0A🖥 主機: <code>$(hostname)</code>"

# 系統資源狀態
MSG="$MSG%0A%0A💻 <b>系統資源</b>"
MSG="$MSG%0A├ CPU: ${MAX_CPU}%% ($MAX_CPU_PROC)"
MSG="$MSG%0A├ 記憶體: ${MEM_USED}/${MEM_TOTAL} (${MEM_PERCENT}%%)"
MSG="$MSG%0A└ 磁碟: ${DISK_USAGE}%% 使用中"

# 安全事件
MSG="$MSG%0A%0A🔐 <b>安全事件</b>"
MSG="$MSG%0A├ 登入次數: $LOGIN_COUNT"
[ -n "$LOGIN_USERS" ] && MSG="$MSG (用戶: $LOGIN_USERS)"
MSG="$MSG%0A├ 登入失敗: $FAILED_LOGIN 次"
MSG="$MSG%0A├ 當前封鎖 IP: $BANNED_COUNT (總計: $TOTAL_BANNED)"
MSG="$MSG%0A├ 敏感檔案變動: $SENSITIVE_COUNT"
MSG="$MSG%0A└ Audit 異常: $AUDIT_EVENTS"

# 威脅掃描
MSG="$MSG%0A%0A🛡 <b>威脅掃描</b>"
MSG="$MSG%0A├ 病毒: $INFECTED_COUNT"
MSG="$MSG%0A├ Rootkit 警告: $ROOTKIT_WARNINGS"
MSG="$MSG%0A└ 惡意軟體: $MALWARE_FOUND"

# 系統維護
MSG="$MSG%0A%0A🔧 <b>系統維護</b>"
MSG="$MSG%0A├ 安全更新: $SECURITY_UPDATES 個"
MSG="$MSG%0A└ 檔案變動 (24h): $FILE_CHANGES_COUNT"

# 添加警告標記
ALERT_LEVEL="🟢 正常"
if [ "$BANNED_COUNT" -gt 5 ] || [ "$INFECTED_COUNT" -gt 0 ] || [ "$ROOTKIT_WARNINGS" -gt 0 ] || [ "$DISK_USAGE" -gt 85 ] || [ "$SENSITIVE_COUNT" -gt 0 ]; then
    ALERT_LEVEL="🔴 需要關注"
fi
if [ "$BANNED_COUNT" -gt 2 ] || [ "$FAILED_LOGIN" -gt 10 ] || [ "$DISK_USAGE" -gt 70 ]; then
    ALERT_LEVEL="🟡 輕微警告"
fi

MSG="$MSG%0A%0A狀態: $ALERT_LEVEL"

# 添加 Lynis 訊息（如果有）
MSG="$MSG$LYNIS_MSG"

# 添加服務異常（如果有）
if [ -n "$FAILED_SERVICES" ]; then
    MSG="$MSG%0A%0A⚠️ 服務異常:$FAILED_SERVICES"
fi

# 添加異常 IP 連線
if [ -n "$SUSPICIOUS_CONN" ]; then
    MSG="$MSG%0A%0A⚠️ 異常連線: $SUSPICIOUS_CONN"
fi

# 添加敏感檔案變動詳情
if [ "$SENSITIVE_COUNT" -gt 0 ]; then
    MSG="$MSG%0A%0A⚠️ 敏感檔案:$SENSITIVE_CHANGES"
fi

MSG="$MSG%0A%0A詳細報告: /opt/security/logs/daily-report-$(date +%Y%m%d).txt"

# 發送 Telegram
/opt/security/scripts/send-telegram.sh "$MSG"

# ===== 清理 30 天前日誌 =====
find /opt/security/logs -name "daily-report-*.txt" -mtime +30 -delete
find /opt/security/logs -name "chkrootkit-*.log" -mtime +30 -delete
find /opt/security/logs -name "maldet-*.log" -mtime +30 -delete
find /opt/security/logs -name "clamav-daily-*.log" -mtime +30 -delete
find /opt/security/logs -name "lynis-*.log" -mtime +30 -delete

# ===== 恢復 process-monitor =====
systemctl start process-monitor

echo "每日檢查完成 - 報告已發送至 Telegram"
EOFF

#########################################
# 深度掃描排程
#########################################
cat > /etc/cron.daily/security-deep-scan << 'EOF'
#!/bin/bash
set -e

LOG="/opt/security/reports/daily-$(date +%F).txt"
SCAN_DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "===== Security Deep Scan Report - $SCAN_DATE =====" > $LOG

# ===== Lynis 掃描 =====
echo "[$(date)] 開始 Lynis 掃描..." >> $LOG
LYNIS_LOG="/opt/security/logs/lynis-deep-$(date +%Y%m%d).log"
nice -n 19 ionice -c3 /opt/lynis/lynis audit system --quiet > $LYNIS_LOG 2>&1
LYNIS_WARNINGS=$(grep -c 'Warning:' $LYNIS_LOG 2>/dev/null || echo 0)
LYNIS_SUGGESTIONS=$(grep -c 'Suggestion:' $LYNIS_LOG 2>/dev/null || echo 0)
cat $LYNIS_LOG >> $LOG

# ===== chkrootkit 掃描 =====
echo "[$(date)] 開始 chkrootkit 掃描..." >> $LOG
CHKROOTKIT_LOG="/opt/security/logs/chkrootkit-deep-$(date +%Y%m%d).log"
nice -n 19 ionice -c3 chkrootkit > $CHKROOTKIT_LOG 2>&1
ROOTKIT_WARNINGS=$(grep -iE "warning|infected|suspicious" $CHKROOTKIT_LOG | wc -l || echo 0)
cat $CHKROOTKIT_LOG >> $LOG

# ===== Maldet 更新 =====
echo "[$(date)] 更新 Maldet 特徵庫..." >> $LOG
maldet -u >> $LOG 2>&1 || true

# ===== Maldet 掃描 =====
echo "[$(date)] 開始 Maldet 掃描..." >> $LOG
MALDET_LOG="/opt/security/logs/maldet-deep-$(date +%Y%m%d).log"
nice -n 19 ionice -c3 maldet -b -r /home /var/www /opt > $MALDET_LOG 2>&1 || true
MALWARE_FOUND=$(grep -iE "malware detected|threats found" $MALDET_LOG | wc -l || echo 0)
cat $MALDET_LOG >> $LOG

# ===== ClamAV 掃描 =====
echo "[$(date)] 開始 ClamAV 掃描..." >> $LOG
INFECTED_COUNT=0
for dir in /home /root /opt /var/www; do
    [ -d "$dir" ] || continue
    CLAMAV_LOG="/opt/security/logs/clamav-deep-$(date +%Y%m%d)-$(basename $dir).log"
    nice -n 19 ionice -c3 clamscan -r "$dir" --infected --quiet > $CLAMAV_LOG 2>&1 || true
    DIR_INFECTED=$(grep -c "FOUND" $CLAMAV_LOG 2>/dev/null || echo 0)
    INFECTED_COUNT=$((INFECTED_COUNT + DIR_INFECTED))
    cat $CLAMAV_LOG >> $LOG
done

# ===== AIDE 檢查 =====
echo "[$(date)] 開始 AIDE 檢查..." >> $LOG
AIDE_LOG="/opt/security/logs/aide-deep-$(date +%Y%m%d).log"
aide --check > $AIDE_LOG 2>&1 || true
AIDE_CHANGES=$(grep -c "changed:" $AIDE_LOG 2>/dev/null || echo 0)
cat $AIDE_LOG >> $LOG

# ===== 掃描完成時間 =====
SCAN_END=$(date '+%Y-%m-%d %H:%M:%S')
echo "[$SCAN_END] 深度掃描完成" >> $LOG

# ===== 構建 Telegram 通知訊息 =====
MSG="🔍 <b>深度安全掃描完成</b> - $(date +%m/%d %H:%M)%0A━━━━━━━━━━━━━━━━"
MSG="$MSG%0A🖥 主機: <code>$(hostname)</code>"
MSG="$MSG%0A⏱ 掃描時間: $SCAN_DATE → $SCAN_END"

# 掃描結果摘要
MSG="$MSG%0A%0A📊 <b>掃描結果摘要</b>"
MSG="$MSG%0A├ 🦠 病毒威脅: $INFECTED_COUNT"
MSG="$MSG%0A├ 🕵️ Rootkit 警告: $ROOTKIT_WARNINGS"
MSG="$MSG%0A├ 🦠 惡意軟體: $MALWARE_FOUND"
MSG="$MSG%0A├ ⚠️ Lynis 警告: $LYNIS_WARNINGS"
MSG="$MSG%0A├ 💡 Lynis 建議: $LYNIS_SUGGESTIONS"
MSG="$MSG%0A└ 📝 AIDE 變更: $AIDE_CHANGES"

# 判斷警告等級
ALERT_LEVEL="🟢 正常"
if [ "$INFECTED_COUNT" -gt 0 ] || [ "$ROOTKIT_WARNINGS" -gt 5 ] || [ "$MALWARE_FOUND" -gt 0 ] || [ "$AIDE_CHANGES" -gt 10 ]; then
    ALERT_LEVEL="🔴 需要立即關注"
elif [ "$ROOTKIT_WARNINGS" -gt 0 ] || [ "$LYNIS_WARNINGS" -gt 10 ] || [ "$AIDE_CHANGES" -gt 5 ]; then
    ALERT_LEVEL="🟡 需要檢查"
fi

MSG="$MSG%0A%0A狀態: $ALERT_LEVEL"

# 如果有威脅，添加詳細資訊
if [ "$INFECTED_COUNT" -gt 0 ]; then
    MSG="$MSG%0A%0A⚠️ <b>發現病毒威脅！</b>"
    MSG="$MSG%0A請查看: /opt/security/logs/clamav-deep-*.log"
fi

if [ "$ROOTKIT_WARNINGS" -gt 0 ]; then
    MSG="$MSG%0A%0A⚠️ <b>Rootkit 警告！</b>"
    MSG="$MSG%0A請查看: /opt/security/logs/chkrootkit-deep-*.log"
fi

if [ "$MALWARE_FOUND" -gt 0 ]; then
    MSG="$MSG%0A%0A⚠️ <b>發現惡意軟體！</b>"
    MSG="$MSG%0A請查看: /opt/security/logs/maldet-deep-*.log"
fi

MSG="$MSG%0A%0A📄 完整報告: $LOG"

# 發送 Telegram 通知
/opt/security/scripts/send-telegram.sh "$MSG"

echo "深度掃描完成，通知已發送 ✅"
EOF

chmod +x /etc/cron.daily/security-deep-scan

#########################################
# 檢查監控服務狀態並確保正常運行
#########################################
echo "檢查 Security Monitor 服務狀態並確保正常運行..."

declare -a SVC=("reverse-shell-detector" "process-monitor" "network-monitor" "file-monitor")
declare -a FAILED_SERVICES=()

# 檢查並修復監控服務
for svc in "${SVC[@]}"; do
    echo "檢查 $svc..."
    
    # 檢查是否啟用開機自動啟動
    if ! systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        echo "  → 啟用開機自動啟動..."
        systemctl enable "$svc" 2>/dev/null || true
    fi
    
    # 檢查是否正在運行
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "  → 啟動服務..."
        systemctl start "$svc" 2>/dev/null || {
            echo "  ⚠️ 無法啟動 $svc"
            FAILED_SERVICES+=("$svc")
            continue
        }
        sleep 1
    fi
    
    # 再次確認狀態
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        STATUS="運行中 ✅"
    else
        STATUS="未啟動 ❌"
        FAILED_SERVICES+=("$svc")
    fi

    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        ENABLED="已啟用開機自動啟動 ✅"
    else
        ENABLED="未啟用開機自動啟動 ❌"
    fi

    echo "  ✓ $svc: $STATUS, $ENABLED"
done

# 檢查 ClamAV 服務
echo "檢查 ClamAV 服務..."
if ! systemctl is-enabled --quiet clamd@scan.service 2>/dev/null; then
    echo "  → 啟用 ClamAV 開機自動啟動..."
    systemctl enable clamd@scan.service 2>/dev/null || true
fi

if ! systemctl is-active --quiet clamd@scan.service 2>/dev/null; then
    echo "  → 啟動 ClamAV 服務..."
    systemctl start clamd@scan.service 2>/dev/null || true
    sleep 2
fi

if systemctl is-active --quiet clamd@scan.service 2>/dev/null; then
    echo "  ✓ clamd@scan: 運行中 ✅, 開機自動啟動: $(systemctl is-enabled clamd@scan.service 2>/dev/null && echo '已啟用 ✅' || echo '未啟用 ❌')"
else
    echo "  ⚠️ clamd@scan: 未啟動 ❌"
    FAILED_SERVICES+=("clamd@scan")
fi

# 顯示最終狀態摘要
echo ""
echo "==========================================="
echo "服務狀態摘要："
echo "==========================================="

for svc in "${SVC[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        STATUS="✅ 運行中"
    else
        STATUS="❌ 未啟動"
    fi
    
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        ENABLED="✅ 開機自動啟動"
    else
        ENABLED="❌ 未啟用開機自動啟動"
    fi
    
    echo "  $svc: $STATUS | $ENABLED"
done

if systemctl is-active --quiet clamd@scan.service 2>/dev/null; then
    echo "  clamd@scan: ✅ 運行中 | $(systemctl is-enabled clamd@scan.service 2>/dev/null && echo '✅ 開機自動啟動' || echo '❌ 未啟用開機自動啟動')"
else
    echo "  clamd@scan: ❌ 未啟動"
fi

# 如果有失敗的服務，顯示警告
if [ ${#FAILED_SERVICES[@]} -gt 0 ]; then
    echo ""
    echo "⚠️ 警告：以下服務無法正常啟動："
    for svc in "${FAILED_SERVICES[@]}"; do
        echo "  - $svc"
    done
    echo "請手動檢查：systemctl status <服務名稱>"
else
    echo ""
    echo "✅ 所有服務運行正常，開機後會自動啟動！"
fi
echo "==========================================="

#########################################
# ===== 設定 crontab =====
#########################################
echo "#設定 crontab"

# 將每日檢查加入 /etc/crontab
# 檢查是否已有註解行，如果沒有則添加註解和命令
if ! grep -q "# Security Monitor - 每日安全檢查" /etc/crontab; then
    # 如果命令已存在但沒有註解，在命令前插入註解
    if grep -q "security-check" /etc/crontab; then
        # 在 security-check 行前插入註解
        sed -i '/security-check/i# Security Monitor - 每日安全檢查 (每天早上 6:30)' /etc/crontab
    else
        # 如果命令不存在，添加註解和命令
        echo "# Security Monitor - 每日安全檢查 (每天早上 6:30)" >> /etc/crontab
        echo "30 6 * * * root /etc/cron.daily/security-check" >> /etc/crontab
    fi
fi

# 將深度掃描加入 /etc/crontab
# 檢查是否已有註解行，如果沒有則添加註解和命令
if ! grep -q "# Security Monitor - 深度安全掃描" /etc/crontab; then
    # 如果命令已存在但沒有註解，在命令前插入註解
    if grep -q "security-deep-scan" /etc/crontab; then
        # 在 security-deep-scan 行前插入註解
        sed -i '/security-deep-scan/i# Security Monitor - 深度安全掃描 (每天凌晨 2:00)' /etc/crontab
    else
        # 如果命令不存在，添加註解和命令
        echo "# Security Monitor - 深度安全掃描 (每天凌晨 2:00)" >> /etc/crontab
        echo "0 2 * * * root /etc/cron.daily/security-deep-scan" >> /etc/crontab
    fi
fi

echo "#設定crontab完成 ✅"

sudo systemctl restart crond.service

#########################################
# 清理暫存和多餘檔案
#########################################
echo "清理暫存與安裝檔案..."

# 確保在穩定目錄
cd /tmp 2>/dev/null || cd / 2>/dev/null || true

# 刪除下載的 tar.gz、zip 檔案
rm -f /opt/lynis.tar.gz
rm -f /opt/security/tools/chkrootkit.zip
rm -f /tmp/maldetect.tar.gz

# 刪除解壓縮後的暫存目錄（只保留最終安裝目錄）
rm -rf /opt/security/tools/chkrootkit-master
rm -rf /tmp/maldetect-*

# 若有舊版本 lynis 目錄，已經被 mv 覆蓋，可額外確保沒有多餘目錄
find /opt -maxdepth 1 -type d -name "lynis-*" ! -name "lynis" -exec rm -rf {} \;

echo "清理完成 ✅"

#########################################

echo "==========================================="
echo "✅ 安裝完成：Security Monitor v3.5"
echo "🚀 即時事件：Telegram"
echo "🛡 深度掃描工具全啟用：Lynis / Maldet / chkrootkit / ClamAV / AIDE"
echo "📝 Log：/opt/security/logs/"
echo "📅 報告：/opt/security/reports/"
echo "==========================================="

# ===== 安裝完成 Telegram 通知 =====
if [ -f /opt/security/config/telegram.token ]; then
    /opt/security/scripts/send-telegram.sh "🎉 <b>監控系統 v${SCRIPT_VERSION} 已安裝</b>%0A主機: $(hostname)%0A時間: $(date '+%Y-%m-%d %H:%M:%S')"
fi

#########################################
#刪除腳本
#########################################
echo "#刪除腳本"
# 確保在穩定目錄
cd /tmp 2>/dev/null || cd / 2>/dev/null || true

# 使用變數記錄的腳本路徑，如果沒有則使用預設路徑
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$SCRIPT_NAME" ]; then
    rm -f "$SCRIPT_DIR/$SCRIPT_NAME"
elif [ -f "/root/install-security-monitor.sh" ]; then
    rm -f /root/install-security-monitor.sh
fi

echo "刪除腳本完成 ✅"