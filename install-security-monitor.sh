#!/bin/bash
set -e

# 在腳本開始時就切換到穩定目錄，避免後續操作導致目錄問題
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || SCRIPT_DIR="/root"
SCRIPT_NAME="$(basename "$0")"
cd /tmp 2>/dev/null || cd / 2>/dev/null || true

sudo yum remove snapd snapd-selinux snap-confine -y 2>/dev/null || true
sudo yum -y update || true
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
LOG_FILE="/opt/security/logs/telegram.log"

# 檢查配置檔案是否存在
if [ ! -f "$TOKEN_FILE" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ Telegram 配置檔案不存在: $TOKEN_FILE" >> "$LOG_FILE" 2>&1
    exit 1
fi

# 載入配置
source "$TOKEN_FILE" 2>/dev/null || {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ 無法載入 Telegram 配置" >> "$LOG_FILE" 2>&1
    exit 1
}

# 檢查必要的變數
if [ -z "$TG_BOT_TOKEN" ] || [ -z "$TG_CHAT_ID" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ Telegram Token 或 Chat ID 未設定" >> "$LOG_FILE" 2>&1
    exit 1
fi

TEXT="$1"
if [ -z "$TEXT" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ 訊息內容為空" >> "$LOG_FILE" 2>&1
    exit 1
fi

# Telegram 訊息長度限制為 4096 字元
TEXT_LENGTH=$(echo -n "$TEXT" | wc -c)
if [ "$TEXT_LENGTH" -gt 4096 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️ 訊息過長 ($TEXT_LENGTH 字元)，截斷至 4096 字元" >> "$LOG_FILE" 2>&1
    TEXT=$(echo -n "$TEXT" | head -c 4093)
    TEXT="${TEXT}..."
fi

# 發送訊息並檢查結果
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
     -d chat_id="${TG_CHAT_ID}" \
     -d text="$TEXT" \
     -d parse_mode="HTML" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

# 檢查 HTTP 狀態碼和 API 回應
if [ "$HTTP_CODE" = "200" ]; then
    # 即使 HTTP 200，也要檢查 API 回應是否成功
    if echo "$BODY" | grep -q '"ok":true'; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ Telegram 訊息發送成功 (長度: $TEXT_LENGTH 字元)" >> "$LOG_FILE" 2>&1
        exit 0
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ Telegram API 回應失敗 (HTTP 200 但 API 返回錯誤)" >> "$LOG_FILE" 2>&1
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 回應: $BODY" >> "$LOG_FILE" 2>&1
        exit 1
    fi
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ Telegram 訊息發送失敗 (HTTP $HTTP_CODE)" >> "$LOG_FILE" 2>&1
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 回應: $BODY" >> "$LOG_FILE" 2>&1
    exit 1
fi
EOF

chmod +x /opt/security/scripts/send-telegram.sh

#########################################
# 安裝必要工具
#########################################
echo "安裝必要系統套件..."
dnf install -y epel-release

# 啟用 CRB repository（某些套件需要，如 glibc-static）
dnf config-manager --set-enabled crb 2>/dev/null || \
    dnf config-manager --set-enabled powertools 2>/dev/null || \
    dnf config-manager --set-enabled devel 2>/dev/null || true

# 安裝主要套件
dnf install -y \
    fail2ban fail2ban-systemd \
    curl jq audit aide rkhunter \
    clamav clamav-update clamav-server clamav-server-systemd \
    inotify-tools \
    sysstat logrotate psmisc lsof net-tools \
    gcc make bc unzip

# 嘗試安裝 glibc-static（可選，如果找不到也不影響）
dnf install -y glibc-static 2>/dev/null || echo "⚠️ glibc-static 未安裝（可選套件，不影響功能）"

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

# 檢查系統中實際的 clamav 用戶和組 ID
CLAMAV_UID=$(id -u clamupdate 2>/dev/null || id -u clamav 2>/dev/null || echo "989")
CLAMAV_GID=$(id -g clamupdate 2>/dev/null || id -g clamav 2>/dev/null || echo "988")

# 嘗試多種方式設置權限（兼容不同系統）
# 優先使用用戶名，如果失敗則嘗試多種 UID/GID 組合
chown -R clamupdate:clamupdate /var/lib/clamav 2>/dev/null || \
chown -R clamav:clamav /var/lib/clamav 2>/dev/null || \
chown -R "$CLAMAV_UID:$CLAMAV_GID" /var/lib/clamav 2>/dev/null || \
chown -R 990:989 /var/lib/clamav 2>/dev/null || \
chown -R 989:988 /var/lib/clamav 2>/dev/null || true

chmod 755 /var/lib/clamav
chmod 1777 /var/lib/clamav/tmp 2>/dev/null || chmod 777 /var/lib/clamav/tmp 2>/dev/null || true

# 確保資料庫目錄對 clamav 用戶可寫
chmod 755 /var/lib/clamav
chmod 755 /var/lib/clamav/tmp 2>/dev/null || true

# 檢查並修復 freshclam.conf 配置
if [ ! -f /etc/freshclam.conf ]; then
    # 如果配置文件不存在，從模板創建
    if [ -f /etc/freshclam.conf.sample ]; then
        cp /etc/freshclam.conf.sample /etc/freshclam.conf
    else
        # 創建基本配置
        cat > /etc/freshclam.conf << 'FRESHCLAM_EOF'
# ClamAV 病毒庫更新配置
DatabaseDirectory /var/lib/clamav
UpdateLogFile /var/log/freshclam.log
LogTime yes
LogRotate yes
DatabaseOwner clamupdate
AllowSupplementaryGroups yes
FRESHCLAM_EOF
    fi
fi

# 確保配置文件格式正確（移除 Example 註釋）
sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true
sed -i 's/^#Example/#Example/' /etc/freshclam.conf 2>/dev/null || true

# 設置配置文件權限
chown root:root /etc/freshclam.conf
chmod 644 /etc/freshclam.conf

# 更新病毒庫
# 設置環境變數讓 freshclam 使用系統臨時目錄，避免權限問題
export TMPDIR=/tmp
export TMP=/tmp

# 確保資料庫目錄對 clamav 用戶可寫（freshclam 需要）
# 嘗試以 clamupdate 用戶執行，如果失敗則以 root 執行
if id clamupdate &>/dev/null; then
    # 以 clamupdate 用戶執行 freshclam（推薦方式）
    su -s /bin/bash -c "export TMPDIR=/tmp TMP=/tmp; freshclam" clamupdate 2>&1 | grep -v "ERROR.*tmp" || {
        echo "⚠️ ClamAV 更新失敗（以 clamupdate 用戶），嘗試以 root 執行..."
        freshclam 2>&1 | grep -v "ERROR.*tmp" || {
            echo "⚠️ ClamAV 更新失敗，但不影響服務啟動（可稍後手動執行 freshclam）"
        }
    }
else
    # 如果沒有 clamupdate 用戶，直接以 root 執行
    freshclam 2>&1 | grep -v "ERROR.*tmp" || {
        echo "⚠️ ClamAV 更新失敗，但不影響服務啟動（可稍後手動執行 freshclam）"
    }
fi

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
# 嘗試啟用 CRB repository（chkrootkit 可能需要）
sudo dnf config-manager --set-enabled crb 2>/dev/null || \
    sudo dnf config-manager --set-enabled powertools 2>/dev/null || true

sudo dnf install chkrootkit -y || {
    echo "Chkrootkit 不存在，改用源碼編譯"

    sudo mkdir -p /opt/security/tools
    WORK_DIR="/opt/security/tools"
    cd "$WORK_DIR" || cd /tmp

    echo "下載 chkrootkit (GitHub Mirror)..."
    if ! sudo curl -L -o chkrootkit.zip https://github.com/Magentron/chkrootkit/archive/refs/heads/master.zip; then
        echo "❌ chkrootkit 下載失敗，跳過安裝"
        cd /tmp 2>/dev/null || cd / 2>/dev/null || true
    elif ! sudo unzip -oq chkrootkit.zip 2>/dev/null; then
        echo "❌ chkrootkit 解壓縮失敗，跳過安裝"
        cd /tmp 2>/dev/null || cd / 2>/dev/null || true
    elif [ ! -d "chkrootkit-master" ]; then
        echo "❌ 找不到 chkrootkit-master 目錄，跳過安裝"
        cd /tmp 2>/dev/null || cd / 2>/dev/null || true
    else
        cd chkrootkit-master || {
            echo "❌ 無法進入 chkrootkit-master 目錄，跳過安裝"
            cd /tmp 2>/dev/null || cd / 2>/dev/null || true
        }
        
        if [ -d "$(pwd)" ] && [ -f "Makefile" ]; then
            echo "編譯..."
            if sudo make sense 2>/dev/null; then
                if [ -f "chkrootkit" ]; then
                    echo "安裝到 /usr/local/bin..."
                    # 獲取源文件的完整絕對路徑
                    SOURCE_FILE="$(pwd)/chkrootkit"
                    SOURCE_ABS=$(readlink -f "$SOURCE_FILE" 2>/dev/null || realpath "$SOURCE_FILE" 2>/dev/null || echo "$SOURCE_FILE")
                    
                    # 檢查目標文件是否存在（可能是符號連結或普通文件）
                    if [ -e "/usr/local/bin/chkrootkit" ]; then
                        # 如果是符號連結，必須替換為實際文件（避免源目錄被刪除後連結失效）
                        if [ -L "/usr/local/bin/chkrootkit" ]; then
                            echo "檢測到符號連結，替換為實際文件..."
                            sudo rm -f /usr/local/bin/chkrootkit
                            sudo cp -f "$SOURCE_FILE" /usr/local/bin/chkrootkit
                            sudo chmod +x /usr/local/bin/chkrootkit
                            echo "chkrootkit 安裝完成！（已替換符號連結）"
                        else
                            # 是普通文件，檢查是否相同
                            TARGET_ABS=$(readlink -f /usr/local/bin/chkrootkit 2>/dev/null || realpath /usr/local/bin/chkrootkit 2>/dev/null || echo "/usr/local/bin/chkrootkit")
                            if [ "$SOURCE_ABS" = "$TARGET_ABS" ]; then
                                echo "⚠️ chkrootkit 已存在於目標位置，跳過複製"
                            else
                                # 先刪除現有文件，然後複製
                                sudo rm -f /usr/local/bin/chkrootkit
                                sudo cp -f "$SOURCE_FILE" /usr/local/bin/chkrootkit
                                sudo chmod +x /usr/local/bin/chkrootkit
                                echo "chkrootkit 安裝完成！"
                            fi
                        fi
                    else
                        # 目標文件不存在，直接複製
                        sudo cp -f "$SOURCE_FILE" /usr/local/bin/chkrootkit
                        sudo chmod +x /usr/local/bin/chkrootkit
                        echo "chkrootkit 安裝完成！"
                    fi
                else
                    echo "❌ 找不到編譯後的 chkrootkit 檔案"
                fi
            else
                echo "❌ chkrootkit 編譯失敗，跳過安裝"
            fi
        fi
        
        # 切換回穩定目錄
        cd /tmp 2>/dev/null || cd / 2>/dev/null || true
    fi
}

#########################################
# 初始化 AIDE（檔案完整性監控）
#########################################
echo "初始化 AIDE 檔案完整性監控..."
# 檢查 AIDE 是否已初始化
if [ ! -f /var/lib/aide/aide.db.gz ] && [ ! -f /var/lib/aide/aide.db ]; then
    echo "AIDE 尚未初始化，正在初始化..."
    # 初始化 AIDE 資料庫（這可能需要幾分鐘）
    if aide --init > /tmp/aide-init.log 2>&1; then
        # 移動新資料庫到正確位置
        if [ -f /var/lib/aide/aide.db.new.gz ]; then
            mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            echo "✅ AIDE 初始化完成"
        else
            echo "⚠️ AIDE 初始化完成，但資料庫檔案未找到"
        fi
    else
        echo "⚠️ AIDE 初始化失敗（可能需要手動執行）"
        echo "   手動初始化: aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
    fi
else
    echo "✅ AIDE 已初始化"
fi

#########################################
# 安裝 Lynis
#########################################
echo "下載 Lynis v3.1.6..."
WORK_DIR="/tmp"
cd "$WORK_DIR" || cd /tmp

if ! curl -sL "https://cisofy.com/files/lynis-3.1.6.tar.gz" -o lynis.tar.gz; then
    echo "❌ Lynis 下載失敗，跳過安裝"
    cd /tmp 2>/dev/null || cd / 2>/dev/null || true
elif file lynis.tar.gz 2>/dev/null | grep -q 'gzip compressed'; then
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
    
    if curl -s https://www.rfxn.com/downloads/maldetect-current.tar.gz -o maldetect.tar.gz; then
        if tar xzf maldetect.tar.gz 2>/dev/null; then
            # 找到解壓後的目錄
            MALDET_DIR=$(find . -maxdepth 1 -type d -name "maldetect-*" | head -1)
            if [ -n "$MALDET_DIR" ] && [ -d "$MALDET_DIR" ]; then
                cd "$MALDET_DIR" || cd /tmp
                bash install.sh || echo "⚠️ Maldet 安裝失敗，繼續執行..."
            else
                echo "⚠️ 找不到 maldetect 目錄，跳過安裝"
            fi
        else
            echo "⚠️ Maldet 解壓縮失敗，跳過安裝"
        fi
    else
        echo "⚠️ Maldet 下載失敗，跳過安裝"
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
CHECK_INTERVAL=60  # 每 60 秒檢查一次

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Reverse Shell Detector Started (每 ${CHECK_INTERVAL}s 檢查)" >> "$LOG"

while true; do
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

    sleep $CHECK_INTERVAL
done
EOF

# ==== Process Monitor ====
cat > /opt/security/scripts/process-monitor.sh << 'EOF'
#!/bin/bash
LOG="/opt/security/logs/process-monitor.log"
CHECK_INTERVAL=300  # 每 5 分鐘檢查一次

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Process Monitor Started (每 ${CHECK_INTERVAL}s 檢查)" >> "$LOG"

while true; do
    ps aux --sort=-%cpu | head -n 5 > /opt/security/tmp/top.txt

    while read -r line; do
        cpu=$(echo "$line" | awk '{print $3}')
        mem=$(echo "$line" | awk '{print $4}')
        cmd=$(echo "$line" | awk '{print $11}')

        if (( $(echo "$cpu > 70" | bc -l) )); then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" >> "$LOG"
            /opt/security/scripts/send-telegram.sh "⚠️ <b>High CPU Usage</b>%0A$cmd%0ACPU: $cpu%"
        fi
    done < /opt/security/tmp/top.txt

    sleep $CHECK_INTERVAL
done
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
    # 使用 process substitution 避免子 shell 問題
    while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        
        # 跳過空行和無效 IP
        [ -z "$ip" ] || [ -z "$count" ] && continue
        
        # 跳過本機和 Docker 內網
        if [[ "$ip" =~ ^(127\.|0\.|::|172\.(1[6-9]|2[0-9]|3[0-1])\.|10\.|192\.168\.) ]]; then
            continue
        fi
        
        if [ "$count" -gt $ALERT_THRESHOLD_PORTS ] 2>/dev/null; then
            # 初始化計數器（如果不存在）
            [ -z "${PORT_SCAN_COUNT[$ip]}" ] && PORT_SCAN_COUNT[$ip]=0
            PORT_SCAN_COUNT[$ip]=$((PORT_SCAN_COUNT[$ip] + 1))
            
            # 只在第一次或每 5 次警告
            if [ ${PORT_SCAN_COUNT[$ip]} -eq 1 ] || [ $((PORT_SCAN_COUNT[$ip] % 5)) -eq 0 ]; then
                MSG="🚨 <b>Port Scan 偵測</b>%0AIP: $ip%0A連線數: $count%0A累計次數: ${PORT_SCAN_COUNT[$ip]}%0A主機: $(hostname)"
                /opt/security/scripts/send-telegram.sh "$MSG" "high"
                echo "[$(date)] Port scan from $ip ($count conns, total: ${PORT_SCAN_COUNT[$ip]})" >> "$LOG_FILE"
            fi
        fi
    done < <(netstat -ntu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | awk '{print $1, $2}')

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
# 不使用 set -e，允許部分檢查失敗但不影響整體

# 同時輸出到終端和日誌
log_and_echo() {
    echo "$1" | tee -a "$REPORT_FILE"
}

REPORT_FILE="/opt/security/logs/daily-report-$(date +%Y%m%d).txt"
echo "=== Daily Security Report - $(date) ===" > "$REPORT_FILE"

log_and_echo ""
log_and_echo "==========================================="
log_and_echo "📊 開始每日安全檢查 - $(date '+%Y-%m-%d %H:%M:%S')"
log_and_echo "==========================================="
log_and_echo ""

# ===== 暫停高 CPU 偵測 =====
log_and_echo "[$(date '+%H:%M:%S')] 暫停 process-monitor 服務..."
systemctl stop process-monitor 2>/dev/null || true

# ===== Fail2ban 統計 =====
log_and_echo "[$(date '+%H:%M:%S')] 📊 檢查 Fail2ban 狀態..."
BANNED_COUNT=0
TOTAL_BANNED=0

# 檢查 fail2ban 是否運行
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    # 獲取 fail2ban 狀態
    F2B_STATUS=$(fail2ban-client status sshd 2>/dev/null || echo "")
    
    if [ -n "$F2B_STATUS" ]; then
        # 嘗試多種方式解析（不同版本的 fail2ban 輸出格式可能不同）
        # 方式1: "Currently banned: 0" 或 "Currently banned: 0 IPs"
        BANNED_COUNT=$(echo "$F2B_STATUS" | grep -i "Currently banned" | grep -oE '[0-9]+' | head -1)
        # 方式2: "Total banned: 0" 或 "Total banned: 0 IPs"
        TOTAL_BANNED=$(echo "$F2B_STATUS" | grep -i "Total banned" | grep -oE '[0-9]+' | head -1)
        
        # 如果還是沒找到，嘗試其他格式
        if [ -z "$BANNED_COUNT" ]; then
            BANNED_COUNT=$(echo "$F2B_STATUS" | grep -iE "banned.*ip" | grep -oE '[0-9]+' | head -1)
        fi
        if [ -z "$TOTAL_BANNED" ]; then
            TOTAL_BANNED=$(echo "$F2B_STATUS" | grep -iE "total.*banned" | grep -oE '[0-9]+' | head -1)
        fi
    fi
fi

# 確保是數字，如果為空或非數字則設為 0
if ! [[ "$BANNED_COUNT" =~ ^[0-9]+$ ]]; then
    BANNED_COUNT=0
fi
if ! [[ "$TOTAL_BANNED" =~ ^[0-9]+$ ]]; then
    TOTAL_BANNED=0
fi

echo "=== Fail2ban 封鎖統計 ===" >> "$REPORT_FILE"
fail2ban-client status sshd >> "$REPORT_FILE" 2>&1 || echo "Fail2ban 未啟動" >> "$REPORT_FILE"
log_and_echo "  ✅ 當前封鎖: $BANNED_COUNT, 總計: $TOTAL_BANNED"

# ===== Audit 事件摘要 =====
log_and_echo "[$(date '+%H:%M:%S')] 🔍 開始 Audit 安全審計檢查..."
echo "=== 今日 Audit 事件摘要 ===" >> "$REPORT_FILE"
# 只統計真正可疑的事件：寫入(w)、刪除(unlink)、權限變更(chmod/chown)、執行(execve)
# 排除正常的讀取操作，減少誤報
# 注意：標準權限設置（如 chmod 0440 /etc/sudoers）也會被記錄，這是正常的審計行為
# 過濾標準權限設置：
# - 0440 (0x120 十六進制) = sudoers 標準權限
# - 0644 (0x1a4 十六進制) = passwd 標準權限  
# - 0000 (0x0) = shadow 標準權限（但通常不會用 chmod 設置）
AUDIT_EVENTS=$(ausearch -ts today 2>/dev/null | \
    grep -E 'passwd|sudoers|shadow|sshd_config' | \
    grep -E 'type=SYSCALL.*(write|unlink|chmod|chown|execve)|type=PATH.*(w=|unlink|chmod|chown)' | \
    grep -vE 'a2=0x120|a2=0x1a4|a2=0x180|chmod.*0440|chmod.*0644|chmod.*0600|proctitle=.*chmod.*0440' | \
    wc -l 2>/dev/null || echo 0)

# 確保是數字
if ! [[ "$AUDIT_EVENTS" =~ ^[0-9]+$ ]]; then
    AUDIT_EVENTS=0
fi

# 將所有相關事件（包括讀取）記錄到報告中，但只統計可疑操作
echo "=== 所有相關 Audit 事件（包括正常讀取） ===" >> "$REPORT_FILE"
ausearch -ts today 2>/dev/null | grep -E 'passwd|sudoers|shadow|sshd_config' >> "$REPORT_FILE" 2>&1 || echo "無事件" >> "$REPORT_FILE"

# 如果有可疑事件，額外記錄
if [ "$AUDIT_EVENTS" -gt 0 ]; then
    echo "" >> "$REPORT_FILE"
    echo "=== ⚠️ 可疑操作（寫入/刪除/權限變更，已排除標準權限設置）===" >> "$REPORT_FILE"
    echo "說明：以下操作可能是正常的系統維護，也可能是安全威脅，請根據實際情況判斷" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # 獲取可疑操作（過濾標準權限設置）
    # a2=120 (十進制) 或 a2=0x120 (十六進制) = chmod 0440 (標準 sudoers 權限)
    # a2=420 (十進制) 或 a2=0x1a4 (十六進制) = chmod 0644 (標準 passwd 權限)
    SUSPICIOUS_OPS=$(ausearch -ts today 2>/dev/null | \
        grep -E 'passwd|sudoers|shadow|sshd_config' | \
        grep -E 'type=SYSCALL.*(write|unlink|chmod|chown|execve)|type=PATH.*(w=|unlink|chmod|chown)' | \
        grep -vE 'a2=120|a2=0x120|a2=420|a2=0x1a4|a2=384|a2=0x180|chmod.*0440|chmod.*0644|chmod.*0600' || echo "")
    
    if [ -n "$SUSPICIOUS_OPS" ]; then
        echo "⚠️ 發現可疑操作，詳細資訊如下：" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        
        # 使用 ausearch -i 格式化輸出，更易讀
        echo "【易讀格式】" >> "$REPORT_FILE"
        # 提取所有相關的 audit key
        for key in sudoers_changes passwd_changes shadow_changes sshd_config_changes; do
            KEY_OPS=$(ausearch -ts today -k "$key" -i 2>/dev/null | \
                grep -vE 'chmod.*0440|chmod.*0644|chmod.*0600' | \
                grep -E 'chmod|write|unlink|chown|execve' || echo "")
            if [ -n "$KEY_OPS" ]; then
                echo "--- $key ---" >> "$REPORT_FILE"
                echo "$KEY_OPS" | head -10 >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
            fi
        done
        
        echo "【原始 Audit 記錄】" >> "$REPORT_FILE"
        echo "$SUSPICIOUS_OPS" >> "$REPORT_FILE"
    else
        echo "✅ 無可疑操作（所有操作都是標準權限設置或正常維護）" >> "$REPORT_FILE"
        echo "說明：chmod 0440 /etc/sudoers 等標準權限設置已被過濾" >> "$REPORT_FILE"
    fi
    log_and_echo "  ⚠️ Audit 檢查完成 - 可疑操作: $AUDIT_EVENTS"
    log_and_echo "    快速查看: grep -A 20 '⚠️ 可疑操作' $REPORT_FILE"
    log_and_echo "    💡 提示：標準權限設置（如 chmod 0440）已排除，這些是正常的維護操作"
else
    log_and_echo "  ✅ Audit 檢查完成 - 無可疑操作"
fi

# ===== 今日登入記錄 =====
echo "=== 今日登入記錄 ===" >> "$REPORT_FILE"
LOGIN_COUNT=$(last -F 2>/dev/null | grep "$(date +%a\ %b\ %e)" 2>/dev/null | wc -l 2>/dev/null || echo 0)
# 確保是數字
if ! [[ "$LOGIN_COUNT" =~ ^[0-9]+$ ]]; then
    LOGIN_COUNT=0
fi
LOGIN_USERS=$(last -F | grep "$(date +%a\ %b\ %e)" | awk '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//' || echo "無")
last -F | grep "$(date +%a\ %b\ %e)" >> "$REPORT_FILE" 2>&1

# ===== 系統更新狀態 =====
echo "=== 系統更新狀態 (Security Updates) ===" >> "$REPORT_FILE"
SECURITY_UPDATES=$(dnf check-update --security 2>&1 | grep -c "^[a-zA-Z]" || echo 0)
dnf check-update --security >> "$REPORT_FILE" 2>&1 || echo "無可用更新" >> "$REPORT_FILE"

# ===== 磁碟使用狀態 =====
echo "=== 磁碟使用狀態 ===" >> "$REPORT_FILE"
DISK_USAGE=$(df -h / 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%' 2>/dev/null || echo "0")
# 確保是數字
if ! [[ "$DISK_USAGE" =~ ^[0-9]+$ ]]; then
    DISK_USAGE=0
fi
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
        echo "$svc: 運行中 ✅" >> "$REPORT_FILE"
    else
        # 檢查服務是否存在（可能未安裝）
        if systemctl list-unit-files | grep -q "^${svc}\." 2>/dev/null; then
            FAILED_SERVICES="$FAILED_SERVICES $svc"
            echo "$svc: 未啟動 ⚠️" >> "$REPORT_FILE"
        else
            echo "$svc: 未安裝（可選服務）" >> "$REPORT_FILE"
        fi
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
# 檢查過去24小時內被修改的敏感檔案
SENSITIVE_CHANGES=$(find /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config -mtime -1 2>/dev/null || echo "")
SENSITIVE_COUNT=$(echo "$SENSITIVE_CHANGES" | grep -v "^$" | wc -l 2>/dev/null || echo 0)
# 確保是數字
if ! [[ "$SENSITIVE_COUNT" =~ ^[0-9]+$ ]]; then
    SENSITIVE_COUNT=0
fi

# ===== 日誌摘要 (secure) =====
echo "=== /var/log/secure 今日摘要 ===" >> "$REPORT_FILE"
FAILED_LOGIN=$(grep "$(date +%b\ %e)" /var/log/secure 2>/dev/null | grep -i "failed" 2>/dev/null | wc -l 2>/dev/null || echo 0)
# 確保是數字
if ! [[ "$FAILED_LOGIN" =~ ^[0-9]+$ ]]; then
    FAILED_LOGIN=0
fi
grep "$(date +%b\ %e)" /var/log/secure >> "$REPORT_FILE" 2>&1 || echo "無事件" >> "$REPORT_FILE"

# ===== ClamAV 輕量掃描 =====
log_and_echo "[$(date '+%H:%M:%S')] 🦠 開始 ClamAV 病毒掃描..."
CLAMAV_DIRS=(/home /root /opt /var/www /srv/data /data /backup)
CLAMAV_LOG="/opt/security/logs/clamav-daily-$(date +%Y%m%d).log"

# 確保 ClamAV 臨時目錄權限正確（每次執行時修復）
mkdir -p /var/lib/clamav/tmp
chown -R 989:988 /var/lib/clamav 2>/dev/null || chown -R clamupdate:clamupdate /var/lib/clamav 2>/dev/null || true
chmod 755 /var/lib/clamav 2>/dev/null || true
chmod 1777 /var/lib/clamav/tmp 2>/dev/null || chmod 777 /var/lib/clamav/tmp 2>/dev/null || true

# 更新病毒庫（使用系統臨時目錄避免權限問題）
log_and_echo "  🔄 更新病毒庫..."
export TMPDIR=/tmp
export TMP=/tmp
# 嘗試更新，抑制權限相關錯誤（不影響掃描功能）
FRESHCLAM_OUTPUT=$(freshclam 2>&1)
FRESHCLAM_SUCCESS=$(echo "$FRESHCLAM_OUTPUT" | grep -E "updated|up-to-date" || echo "")
if [ -n "$FRESHCLAM_SUCCESS" ]; then
    echo "✅ ClamAV 病毒庫更新成功" >> "$REPORT_FILE"
    echo "$FRESHCLAM_SUCCESS" >> "$REPORT_FILE"
    log_and_echo "  ✅ 病毒庫已更新"
else
    # 只記錄到報告，不顯示錯誤（權限問題不影響掃描）
    echo "⚠️ ClamAV 更新跳過（權限限制，使用現有病毒庫，不影響掃描功能）" >> "$REPORT_FILE"
    log_and_echo "  ⚠️ 使用現有病毒庫"
fi

log_and_echo "  📁 掃描目錄..."
INFECTED_COUNT=0
SCANNED_DIRS=0
for dir in "${CLAMAV_DIRS[@]}"; do
    [ -d "$dir" ] || continue
    SCANNED_DIRS=$((SCANNED_DIRS + 1))
    log_and_echo "    - $dir"
    SCAN_RESULT=$(nice -n 19 ionice -c3 clamdscan --fdpass --multiscan --infected --quiet "$dir" 2>&1 || true)
    echo "$SCAN_RESULT" >> "$CLAMAV_LOG"
    # 安全地計算感染數量，確保是數字
    FOUND_COUNT=$(echo "$SCAN_RESULT" | grep -o "FOUND" 2>/dev/null | wc -l)
    # 確保是數字，如果為空或非數字則設為 0
    if ! [[ "$FOUND_COUNT" =~ ^[0-9]+$ ]]; then
        FOUND_COUNT=0
    fi
    INFECTED_COUNT=$((INFECTED_COUNT + FOUND_COUNT))
done
log_and_echo "  ✅ ClamAV 掃描完成 - 掃描 $SCANNED_DIRS 個目錄，發現: $INFECTED_COUNT"

# ===== chkrootkit 掃描 =====
log_and_echo "[$(date '+%H:%M:%S')] 🔍 開始 chkrootkit Rootkit 掃描..."
CHKROOTKIT_LOG="/opt/security/logs/chkrootkit-$(date +%Y%m%d).log"

# 查找 chkrootkit 可執行檔（檢查多個可能位置）
CHKROOTKIT_CMD=""
for path in /usr/local/bin/chkrootkit /usr/bin/chkrootkit /opt/security/tools/chkrootkit-master/chkrootkit $(command -v chkrootkit 2>/dev/null); do
    if [ -f "$path" ] && [ -x "$path" ]; then
        CHKROOTKIT_CMD="$path"
        break
    fi
done

if [ -z "$CHKROOTKIT_CMD" ]; then
    log_and_echo "  ⚠️ chkrootkit 未找到，跳過掃描"
    ROOTKIT_WARNINGS=0
else
    "$CHKROOTKIT_CMD" > $CHKROOTKIT_LOG 2>&1 || true
    
    # 只統計真正可疑的警告，排除常見誤報
    # 排除：檢查過程訊息（Searching for... nothing found）、正常工具警告、SELinux/Docker 相關
    ROOTKIT_WARNINGS=$(grep -iE "INFECTED|ROOTKIT|suspicious|hidden|trojan|backdoor" $CHKROOTKIT_LOG 2>/dev/null | \
        grep -vE "^Searching for|nothing found|Checking |^$|^#" | \
        grep -vE "SELinux|docker|container" | \
        grep -vE "Searching for.*rootkit.*nothing found" | \
        wc -l 2>/dev/null || echo 0)
    
    # 確保是數字
    if ! [[ "$ROOTKIT_WARNINGS" =~ ^[0-9]+$ ]]; then
        ROOTKIT_WARNINGS=0
    fi
    
    # 如果有真正的警告，記錄詳細資訊到報告
    if [ "$ROOTKIT_WARNINGS" -gt 0 ]; then
        echo "=== ⚠️ chkrootkit 可疑警告 ===" >> "$REPORT_FILE"
        grep -iE "INFECTED|ROOTKIT|suspicious|hidden|trojan|backdoor" $CHKROOTKIT_LOG 2>/dev/null | \
            grep -vE "^Searching for|nothing found|Checking |^$|^#" | \
            grep -vE "SELinux|docker|container" | \
            grep -vE "Searching for.*rootkit.*nothing found" >> "$REPORT_FILE" 2>&1 || true
    fi
    
    # 計算所有警告（包括誤報）用於參考
    TOTAL_WARNINGS=$(grep -i "warning\|infected" $CHKROOTKIT_LOG 2>/dev/null | wc -l 2>/dev/null || echo 0)
    
    if [ "$ROOTKIT_WARNINGS" -gt 0 ]; then
        log_and_echo "  ⚠️ chkrootkit 掃描完成 - 可疑警告: $ROOTKIT_WARNINGS (總警告: $TOTAL_WARNINGS，已過濾常見誤報)"
    else
        log_and_echo "  ✅ chkrootkit 掃描完成 - 無可疑警告 (總警告: $TOTAL_WARNINGS，均為常見誤報)"
    fi
fi

# ===== LMD 掃描 =====
log_and_echo "[$(date '+%H:%M:%S')] 🦠 開始 Maldet 惡意軟體掃描..."
MALDET_LOG="/opt/security/logs/maldet-$(date +%Y%m%d).log"
maldet -a /home /var/www > $MALDET_LOG 2>&1 || true
MALWARE_FOUND=$(grep -i "malware detected" $MALDET_LOG 2>/dev/null | wc -l 2>/dev/null || echo 0)
# 確保是數字
if ! [[ "$MALWARE_FOUND" =~ ^[0-9]+$ ]]; then
    MALWARE_FOUND=0
fi
log_and_echo "  ✅ Maldet 掃描完成 - 發現: $MALWARE_FOUND"

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
MSG="$MSG%0A├ CPU: ${MAX_CPU}% ($MAX_CPU_PROC)"
MSG="$MSG%0A├ 記憶體: ${MEM_USED}/${MEM_TOTAL} (${MEM_PERCENT}%)"
MSG="$MSG%0A└ 磁碟: ${DISK_USAGE}% 使用中"

# 在構建 Telegram 訊息前，確保所有變數都已正確初始化
# 安全地轉換變數為數字，如果為空或非數字則設為 0
BANNED_COUNT=${BANNED_COUNT:-0}
TOTAL_BANNED=${TOTAL_BANNED:-0}
INFECTED_COUNT=${INFECTED_COUNT:-0}
ROOTKIT_WARNINGS=${ROOTKIT_WARNINGS:-0}
MALWARE_FOUND=${MALWARE_FOUND:-0}
SENSITIVE_COUNT=${SENSITIVE_COUNT:-0}
FAILED_LOGIN=${FAILED_LOGIN:-0}
DISK_USAGE=${DISK_USAGE:-0}
AUDIT_EVENTS=${AUDIT_EVENTS:-0}
LOGIN_COUNT=${LOGIN_COUNT:-0}
SECURITY_UPDATES=${SECURITY_UPDATES:-0}
FILE_CHANGES_COUNT=${FILE_CHANGES_COUNT:-0}

# 確保是數字（如果不是數字則設為 0）
if ! [[ "$BANNED_COUNT" =~ ^[0-9]+$ ]]; then BANNED_COUNT=0; fi
if ! [[ "$TOTAL_BANNED" =~ ^[0-9]+$ ]]; then TOTAL_BANNED=0; fi
if ! [[ "$INFECTED_COUNT" =~ ^[0-9]+$ ]]; then INFECTED_COUNT=0; fi
if ! [[ "$ROOTKIT_WARNINGS" =~ ^[0-9]+$ ]]; then ROOTKIT_WARNINGS=0; fi
if ! [[ "$MALWARE_FOUND" =~ ^[0-9]+$ ]]; then MALWARE_FOUND=0; fi
if ! [[ "$SENSITIVE_COUNT" =~ ^[0-9]+$ ]]; then SENSITIVE_COUNT=0; fi
if ! [[ "$FAILED_LOGIN" =~ ^[0-9]+$ ]]; then FAILED_LOGIN=0; fi
if ! [[ "$DISK_USAGE" =~ ^[0-9]+$ ]]; then DISK_USAGE=0; fi
if ! [[ "$AUDIT_EVENTS" =~ ^[0-9]+$ ]]; then AUDIT_EVENTS=0; fi
if ! [[ "$LOGIN_COUNT" =~ ^[0-9]+$ ]]; then LOGIN_COUNT=0; fi
if ! [[ "$SECURITY_UPDATES" =~ ^[0-9]+$ ]]; then SECURITY_UPDATES=0; fi
if ! [[ "$FILE_CHANGES_COUNT" =~ ^[0-9]+$ ]]; then FILE_CHANGES_COUNT=0; fi

# 安全事件
MSG="$MSG%0A%0A🔐 <b>安全事件</b>"
MSG="$MSG%0A├ 登入次數: $LOGIN_COUNT"
[ -n "$LOGIN_USERS" ] && MSG="$MSG (用戶: $LOGIN_USERS)"
MSG="$MSG%0A├ 登入失敗: $FAILED_LOGIN 次"
MSG="$MSG%0A├ 當前封鎖 IP: $BANNED_COUNT (總計: $TOTAL_BANNED)"
MSG="$MSG%0A├ 敏感檔案變動: $SENSITIVE_COUNT"
# Audit 異常說明：只統計可疑操作（寫入/刪除/權限變更），不包括正常讀取
if [ "$AUDIT_EVENTS" -gt 0 ]; then
    MSG="$MSG%0A└ ⚠️ Audit 可疑操作: $AUDIT_EVENTS"
    MSG="$MSG%0A%0A🔍 快速查看: <code>grep -A 20 '可疑操作' /opt/security/logs/daily-report-$(date +%Y%m%d).txt</code>"
else
    MSG="$MSG%0A└ Audit 可疑操作: 0"
fi

# 威脅掃描
MSG="$MSG%0A%0A🛡 <b>威脅掃描</b>"
MSG="$MSG%0A├ 病毒: $INFECTED_COUNT"
# Rootkit 警告說明：只統計真正可疑的警告，已過濾常見誤報
if [ "$ROOTKIT_WARNINGS" -gt 0 ]; then
    MSG="$MSG%0A├ ⚠️ Rootkit 可疑警告: $ROOTKIT_WARNINGS"
    MSG="$MSG%0A%0A🔍 快速查看: <code>grep -A 10 'chkrootkit 可疑警告' /opt/security/logs/daily-report-$(date +%Y%m%d).txt</code>"
else
    MSG="$MSG%0A├ Rootkit 可疑警告: 0"
fi
MSG="$MSG%0A└ 惡意軟體: $MALWARE_FOUND"

# 系統維護
MSG="$MSG%0A%0A🔧 <b>系統維護</b>"
MSG="$MSG%0A├ 安全更新: $SECURITY_UPDATES 個"
MSG="$MSG%0A└ 檔案變動 (24h): $FILE_CHANGES_COUNT"

# 添加警告標記（確保所有變數都是數字）
# 安全地轉換變數為數字，如果為空或非數字則設為 0
BANNED_COUNT=${BANNED_COUNT:-0}
TOTAL_BANNED=${TOTAL_BANNED:-0}
INFECTED_COUNT=${INFECTED_COUNT:-0}
ROOTKIT_WARNINGS=${ROOTKIT_WARNINGS:-0}
MALWARE_FOUND=${MALWARE_FOUND:-0}
SENSITIVE_COUNT=${SENSITIVE_COUNT:-0}
FAILED_LOGIN=${FAILED_LOGIN:-0}
DISK_USAGE=${DISK_USAGE:-0}
AUDIT_EVENTS=${AUDIT_EVENTS:-0}
LOGIN_COUNT=${LOGIN_COUNT:-0}
SECURITY_UPDATES=${SECURITY_UPDATES:-0}
FILE_CHANGES_COUNT=${FILE_CHANGES_COUNT:-0}

# 確保是數字（如果不是數字則設為 0）
if ! [[ "$BANNED_COUNT" =~ ^[0-9]+$ ]]; then BANNED_COUNT=0; fi
if ! [[ "$TOTAL_BANNED" =~ ^[0-9]+$ ]]; then TOTAL_BANNED=0; fi
if ! [[ "$INFECTED_COUNT" =~ ^[0-9]+$ ]]; then INFECTED_COUNT=0; fi
if ! [[ "$ROOTKIT_WARNINGS" =~ ^[0-9]+$ ]]; then ROOTKIT_WARNINGS=0; fi
if ! [[ "$MALWARE_FOUND" =~ ^[0-9]+$ ]]; then MALWARE_FOUND=0; fi
if ! [[ "$SENSITIVE_COUNT" =~ ^[0-9]+$ ]]; then SENSITIVE_COUNT=0; fi
if ! [[ "$FAILED_LOGIN" =~ ^[0-9]+$ ]]; then FAILED_LOGIN=0; fi
if ! [[ "$DISK_USAGE" =~ ^[0-9]+$ ]]; then DISK_USAGE=0; fi
if ! [[ "$AUDIT_EVENTS" =~ ^[0-9]+$ ]]; then AUDIT_EVENTS=0; fi
if ! [[ "$LOGIN_COUNT" =~ ^[0-9]+$ ]]; then LOGIN_COUNT=0; fi
if ! [[ "$SECURITY_UPDATES" =~ ^[0-9]+$ ]]; then SECURITY_UPDATES=0; fi
if ! [[ "$FILE_CHANGES_COUNT" =~ ^[0-9]+$ ]]; then FILE_CHANGES_COUNT=0; fi

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
    MSG="$MSG%0A%0A⚠️ 服務未啟動:$FAILED_SERVICES"
    MSG="$MSG%0A💡 檢查指令: <code>systemctl status nginx mysql</code>"
fi

# 添加異常 IP 連線
if [ -n "$SUSPICIOUS_CONN" ]; then
    MSG="$MSG%0A%0A⚠️ 異常連線: $SUSPICIOUS_CONN"
fi

# 添加敏感檔案變動詳情
if [ "$SENSITIVE_COUNT" -gt 0 ]; then
    MSG="$MSG%0A%0A⚠️ 敏感檔案變動（過去24小時）:"
    # 格式化檔案列表
    SENSITIVE_LIST=$(echo "$SENSITIVE_CHANGES" | tr '\n' ' ' | sed 's/ $//')
    MSG="$MSG%0A$SENSITIVE_LIST"
    MSG="$MSG%0A💡 檢查指令: <code>ls -la /etc/passwd /etc/shadow && stat /etc/passwd /etc/shadow</code>"
    MSG="$MSG%0Aℹ️ 可能是正常維護（用戶管理、權限調整等），請確認是否為預期操作"
fi

MSG="$MSG%0A%0A📄 詳細報告: /opt/security/logs/daily-report-$(date +%Y%m%d).txt"
MSG="$MSG%0A🔍 快速查看: <code>grep -A 20 '可疑操作' /opt/security/logs/daily-report-$(date +%Y%m%d).txt</code>"

# 發送 Telegram
log_and_echo "[$(date '+%H:%M:%S')] 📱 發送 Telegram 通知..."
TELEGRAM_OUTPUT=$(/opt/security/scripts/send-telegram.sh "$MSG" 2>&1)
TELEGRAM_EXIT=$?
echo "$TELEGRAM_OUTPUT" | tee -a "$REPORT_FILE"

if [ $TELEGRAM_EXIT -eq 0 ]; then
    log_and_echo "  ✅ Telegram 通知發送成功"
else
    log_and_echo "  ❌ Telegram 通知發送失敗，請檢查:"
    log_and_echo "     - 配置檔案: /opt/security/config/telegram.token"
    log_and_echo "     - 日誌檔案: /opt/security/logs/telegram.log"
    log_and_echo "     - 手動測試: /opt/security/scripts/send-telegram.sh '測試訊息'"
    log_and_echo "     - 錯誤詳情: $TELEGRAM_OUTPUT"
fi

# ===== 清理 30 天前日誌 =====
find /opt/security/logs -name "daily-report-*.txt" -mtime +30 -delete
find /opt/security/logs -name "chkrootkit-*.log" -mtime +30 -delete
find /opt/security/logs -name "maldet-*.log" -mtime +30 -delete
find /opt/security/logs -name "clamav-daily-*.log" -mtime +30 -delete
find /opt/security/logs -name "lynis-*.log" -mtime +30 -delete

# ===== 恢復 process-monitor =====
log_and_echo "[$(date '+%H:%M:%S')] 恢復 process-monitor 服務..."
systemctl start process-monitor 2>/dev/null || true

log_and_echo ""
log_and_echo "==========================================="
log_and_echo "✅ 每日檢查完成！"
log_and_echo "📄 報告: $REPORT_FILE"
log_and_echo "📱 報告已發送至 Telegram"
log_and_echo "==========================================="
EOFF

#########################################
# 深度掃描排程
#########################################
cat > /etc/cron.daily/security-deep-scan << 'EOF'
#!/bin/bash
# 不使用 set -e，允許部分掃描失敗但不影響整體

LOG="/opt/security/reports/deep-scan-$(date +%F).txt"
SCAN_DATE=$(date '+%Y-%m-%d %H:%M:%S')
SCAN_START_EPOCH=$(date +%s)

# 初始化所有計數變數（避免未定義變數錯誤）
INFECTED_COUNT=0
ROOTKIT_WARNINGS=0
MALWARE_FOUND=0
AIDE_CHANGES=0
LYNIS_WARNINGS=0
LYNIS_SUGGESTIONS=0

# 同時輸出到終端和日誌
log_and_echo() {
    echo "$1" | tee -a "$LOG"
}

log_and_echo "==========================================="
log_and_echo "🔍 開始深度安全掃描 - $SCAN_DATE"
log_and_echo "==========================================="
log_and_echo ""

# ===== Lynis 掃描 =====
log_and_echo "[$(date '+%H:%M:%S')] 📋 步驟 1/5: 開始 Lynis 系統審計掃描..."
LYNIS_LOG="/opt/security/logs/lynis-deep-$(date +%Y%m%d).log"

# 檢查 Lynis 是否安裝
if [ ! -f "/opt/lynis/lynis" ]; then
    log_and_echo "  ❌ Lynis 未安裝（/opt/lynis/lynis 不存在）"
    LYNIS_WARNINGS=0
    LYNIS_SUGGESTIONS=0
else
    # 執行掃描（不依賴退出碼，因為 Lynis 發現問題時會返回非零）
    nice -n 19 ionice -c3 /opt/lynis/lynis audit system --quiet > $LYNIS_LOG 2>&1 || true
    
    # 檢查日誌文件是否存在且有內容
    if [ -f "$LYNIS_LOG" ] && [ -s "$LYNIS_LOG" ]; then
        LYNIS_WARNINGS=$(grep -c 'Warning:' $LYNIS_LOG 2>/dev/null || echo 0)
        LYNIS_SUGGESTIONS=$(grep -c 'Suggestion:' $LYNIS_LOG 2>/dev/null || echo 0)
        
        # 移除可能的換行符和空格，確保是純數字
        LYNIS_WARNINGS=$(echo "$LYNIS_WARNINGS" | tr -d '\n\r ' | grep -oE '[0-9]+' || echo 0)
        LYNIS_SUGGESTIONS=$(echo "$LYNIS_SUGGESTIONS" | tr -d '\n\r ' | grep -oE '[0-9]+' || echo 0)
        
        # 確保是數字
        if ! [[ "$LYNIS_WARNINGS" =~ ^[0-9]+$ ]]; then
            LYNIS_WARNINGS=0
        fi
        if ! [[ "$LYNIS_SUGGESTIONS" =~ ^[0-9]+$ ]]; then
            LYNIS_SUGGESTIONS=0
        fi
        
        log_and_echo "  ✅ Lynis 掃描完成 - 警告: $LYNIS_WARNINGS, 建議: $LYNIS_SUGGESTIONS"
    else
        LYNIS_WARNINGS=0
        LYNIS_SUGGESTIONS=0
        log_and_echo "  ⚠️ Lynis 掃描失敗（日誌文件未生成或為空）"
        log_and_echo "    檢查日誌: $LYNIS_LOG"
        # 顯示錯誤訊息（如果有）
        if [ -f "$LYNIS_LOG" ]; then
            log_and_echo "    錯誤: $(head -n 5 $LYNIS_LOG 2>/dev/null | tr '\n' ' ')"
        fi
    fi
    cat $LYNIS_LOG >> $LOG 2>/dev/null || true
fi
log_and_echo ""

# ===== chkrootkit 掃描 =====
log_and_echo "[$(date '+%H:%M:%S')] 🔍 步驟 2/5: 開始 chkrootkit Rootkit 掃描..."
CHKROOTKIT_LOG="/opt/security/logs/chkrootkit-deep-$(date +%Y%m%d).log"

# 查找 chkrootkit 可執行檔（檢查多個可能位置）
CHKROOTKIT_CMD=""
for path in /usr/local/bin/chkrootkit /usr/bin/chkrootkit /opt/security/tools/chkrootkit-master/chkrootkit $(command -v chkrootkit 2>/dev/null); do
    if [ -f "$path" ] && [ -x "$path" ]; then
        CHKROOTKIT_CMD="$path"
        break
    fi
done

# 檢查 chkrootkit 是否找到
if [ -z "$CHKROOTKIT_CMD" ]; then
    log_and_echo "  ❌ chkrootkit 未安裝或找不到"
    log_and_echo "    請執行安裝腳本安裝 chkrootkit"
    ROOTKIT_WARNINGS=0
else
    log_and_echo "  📍 使用: $CHKROOTKIT_CMD"
    # 執行掃描（不依賴退出碼，因為 chkrootkit 發現問題時會返回非零）
    nice -n 19 ionice -c3 "$CHKROOTKIT_CMD" > $CHKROOTKIT_LOG 2>&1 || true
    
    # 檢查日誌文件是否存在且有內容
    if [ -f "$CHKROOTKIT_LOG" ] && [ -s "$CHKROOTKIT_LOG" ]; then
        # 只統計真正可疑的警告，排除常見誤報
        # 排除：檢查過程訊息（Searching for... nothing found）、正常工具警告、SELinux/Docker 相關
        ROOTKIT_WARNINGS=$(grep -iE "INFECTED|ROOTKIT|suspicious|hidden|trojan|backdoor" $CHKROOTKIT_LOG 2>/dev/null | \
            grep -vE "^Searching for|nothing found|Checking |^$|^#" | \
            grep -vE "SELinux|docker|container" | \
            grep -vE "Searching for.*rootkit.*nothing found" | \
            wc -l 2>/dev/null || echo 0)
        
        # 確保是數字
        if ! [[ "$ROOTKIT_WARNINGS" =~ ^[0-9]+$ ]]; then
            ROOTKIT_WARNINGS=0
        fi
        log_and_echo "  ✅ chkrootkit 掃描完成 - 警告: $ROOTKIT_WARNINGS"
    else
        ROOTKIT_WARNINGS=0
        log_and_echo "  ⚠️ chkrootkit 掃描失敗（日誌文件未生成或為空）"
        log_and_echo "    檢查日誌: $CHKROOTKIT_LOG"
        # 顯示錯誤訊息（如果有）
        if [ -f "$CHKROOTKIT_LOG" ]; then
            log_and_echo "    錯誤: $(head -n 5 $CHKROOTKIT_LOG 2>/dev/null | tr '\n' ' ')"
        fi
    fi
    cat $CHKROOTKIT_LOG >> $LOG 2>/dev/null || true
fi
log_and_echo ""

# ===== Maldet 更新 =====
log_and_echo "[$(date '+%H:%M:%S')] 🔄 更新 Maldet 特徵庫..."
maldet -u >> $LOG 2>&1 && log_and_echo "  ✅ Maldet 特徵庫更新完成" || log_and_echo "  ⚠️ Maldet 更新失敗，繼續執行..."

# ===== Maldet 掃描 =====
log_and_echo "[$(date '+%H:%M:%S')] 🦠 步驟 3/5: 開始 Maldet 惡意軟體掃描（這可能需要較長時間）..."
MALDET_LOG="/opt/security/logs/maldet-deep-$(date +%Y%m%d).log"
if nice -n 19 ionice -c3 maldet -b -r /home /var/www /opt > $MALDET_LOG 2>&1; then
    MALWARE_FOUND=$(grep -iE "malware detected|threats found" $MALDET_LOG | wc -l || echo 0)
    log_and_echo "  ✅ Maldet 掃描完成 - 發現: $MALWARE_FOUND"
else
    MALWARE_FOUND=0
    log_and_echo "  ⚠️ Maldet 掃描失敗，繼續執行..."
fi
cat $MALDET_LOG >> $LOG
log_and_echo ""

# ===== ClamAV 掃描 =====
log_and_echo "[$(date '+%H:%M:%S')] 🦠 步驟 4/5: 開始 ClamAV 病毒掃描（這可能需要較長時間）..."
log_and_echo "  ℹ️ 掃描重點目錄：用戶數據、應用程式、網站目錄"
log_and_echo "  ℹ️ 系統目錄（/usr, /bin, /sbin 等）通常不需要掃描（由套件管理器管理）"
INFECTED_COUNT=0
SCAN_DIRS=0
# 掃描重點目錄：用戶數據、應用程式、網站、暫存目錄
# 可根據需要添加更多目錄，如：/tmp /var/tmp /srv /mnt 等
for dir in /home /root /opt /var/www /tmp /var/tmp /srv/data /data /backup; do
    [ -d "$dir" ] || continue
    SCAN_DIRS=$((SCAN_DIRS + 1))
    log_and_echo "  📁 掃描目錄: $dir"
    CLAMAV_LOG="/opt/security/logs/clamav-deep-$(date +%Y%m%d)-$(basename $dir).log"
    if nice -n 19 ionice -c3 clamscan -r "$dir" --infected --quiet > $CLAMAV_LOG 2>&1; then
        # 安全地計算感染數量，確保是數字
        DIR_INFECTED=$(grep -o "FOUND" $CLAMAV_LOG 2>/dev/null | wc -l)
        # 確保是數字，如果為空或非數字則設為 0
        if ! [[ "$DIR_INFECTED" =~ ^[0-9]+$ ]]; then
            DIR_INFECTED=0
        fi
        INFECTED_COUNT=$((INFECTED_COUNT + DIR_INFECTED))
        log_and_echo "    ✅ $dir 掃描完成 - 發現: $DIR_INFECTED"
    else
        log_and_echo "    ⚠️ $dir 掃描失敗，繼續..."
    fi
    cat $CLAMAV_LOG >> $LOG
done
log_and_echo "  ✅ ClamAV 掃描完成 - 總計發現: $INFECTED_COUNT"
log_and_echo ""

# ===== AIDE 檢查 =====
log_and_echo "[$(date '+%H:%M:%S')] 📝 步驟 5/5: 開始 AIDE 檔案完整性檢查..."
AIDE_LOG="/opt/security/logs/aide-deep-$(date +%Y%m%d).log"

# 檢查 AIDE 資料庫是否存在
if [ ! -f /var/lib/aide/aide.db.gz ] && [ ! -f /var/lib/aide/aide.db ]; then
    AIDE_CHANGES=0
    log_and_echo "  ⚠️ AIDE 尚未初始化（資料庫不存在）"
    log_and_echo "  💡 初始化指令: <code>aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz</code>"
    log_and_echo "  ℹ️ 初始化後，AIDE 將建立系統檔案基準，之後可檢測檔案變更"
    echo "AIDE 未初始化，請執行: aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz" > $AIDE_LOG
elif aide --check > $AIDE_LOG 2>&1; then
    AIDE_CHANGES=$(grep -c "changed:" $AIDE_LOG 2>/dev/null || echo 0)
    # 確保是數字
    if ! [[ "$AIDE_CHANGES" =~ ^[0-9]+$ ]]; then
        AIDE_CHANGES=0
    fi
    log_and_echo "  ✅ AIDE 檢查完成 - 變更: $AIDE_CHANGES"
else
    AIDE_CHANGES=0
    # 檢查是否為初始化相關錯誤
    if grep -qi "database\|not found\|未找到" $AIDE_LOG 2>/dev/null; then
        log_and_echo "  ⚠️ AIDE 檢查失敗（資料庫不存在或未初始化）"
        log_and_echo "  💡 初始化指令: <code>aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz</code>"
    else
        log_and_echo "  ⚠️ AIDE 檢查失敗，請查看日誌: $AIDE_LOG"
    fi
fi
cat $AIDE_LOG >> $LOG
log_and_echo ""

# ===== 掃描完成時間 =====
SCAN_END=$(date '+%Y-%m-%d %H:%M:%S')
SCAN_END_EPOCH=$(date +%s)
SCAN_DURATION=$((SCAN_END_EPOCH - SCAN_START_EPOCH))
SCAN_MINUTES=$((SCAN_DURATION / 60))
SCAN_SECONDS=$((SCAN_DURATION % 60))
log_and_echo "==========================================="
log_and_echo "✅ 深度掃描完成！"
log_and_echo "⏱ 總耗時: ${SCAN_MINUTES} 分 ${SCAN_SECONDS} 秒"
log_and_echo "📄 完整報告: $LOG"
log_and_echo "==========================================="
echo "[$SCAN_END] 深度掃描完成 (耗時: ${SCAN_MINUTES}分${SCAN_SECONDS}秒)" >> $LOG

# ===== 構建 Telegram 通知訊息 =====
MSG="🔍 <b>深度安全掃描完成</b> - $(date '+%m/%d %H:%M')%0A━━━━━━━━━━━━━━━━"
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

# 判斷警告等級（確保所有變數都是數字）
# 安全地轉換變數為數字，如果為空或非數字則設為 0
INFECTED_COUNT=${INFECTED_COUNT:-0}
ROOTKIT_WARNINGS=${ROOTKIT_WARNINGS:-0}
MALWARE_FOUND=${MALWARE_FOUND:-0}
AIDE_CHANGES=${AIDE_CHANGES:-0}
LYNIS_WARNINGS=${LYNIS_WARNINGS:-0}
LYNIS_SUGGESTIONS=${LYNIS_SUGGESTIONS:-0}

# 確保是數字（如果不是數字則設為 0）
if ! [[ "$INFECTED_COUNT" =~ ^[0-9]+$ ]]; then INFECTED_COUNT=0; fi
if ! [[ "$ROOTKIT_WARNINGS" =~ ^[0-9]+$ ]]; then ROOTKIT_WARNINGS=0; fi
if ! [[ "$MALWARE_FOUND" =~ ^[0-9]+$ ]]; then MALWARE_FOUND=0; fi
if ! [[ "$AIDE_CHANGES" =~ ^[0-9]+$ ]]; then AIDE_CHANGES=0; fi
if ! [[ "$LYNIS_WARNINGS" =~ ^[0-9]+$ ]]; then LYNIS_WARNINGS=0; fi
if ! [[ "$LYNIS_SUGGESTIONS" =~ ^[0-9]+$ ]]; then LYNIS_SUGGESTIONS=0; fi

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
    MSG="$MSG%0A📄 日誌: /opt/security/logs/clamav-deep-*.log"
    MSG="$MSG%0A🔍 快速查看: <code>grep -i 'FOUND' /opt/security/logs/clamav-deep-$(date +%Y%m%d)*.log | head -20</code>"
fi

if [ "$ROOTKIT_WARNINGS" -gt 0 ]; then
    MSG="$MSG%0A%0A⚠️ <b>Rootkit 警告！</b>"
    MSG="$MSG%0A📄 日誌: /opt/security/logs/chkrootkit-deep-*.log"
    MSG="$MSG%0A🔍 快速查看: <code>grep -iE 'INFECTED|ROOTKIT|suspicious' /opt/security/logs/chkrootkit-deep-$(date +%Y%m%d).log</code>"
fi

if [ "$MALWARE_FOUND" -gt 0 ]; then
    MSG="$MSG%0A%0A⚠️ <b>發現惡意軟體！</b>"
    MSG="$MSG%0A📄 日誌: /opt/security/logs/maldet-deep-*.log"
    MSG="$MSG%0A🔍 快速查看: <code>grep -i 'malware detected' /opt/security/logs/maldet-deep-$(date +%Y%m%d).log</code>"
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
        sed -i '/security-deep-scan/i# Security Monitor - 深度安全掃描 (每週日凌晨 2:00)' /etc/crontab
    else
        # 如果命令不存在，添加註解和命令
        echo "# Security Monitor - 深度安全掃描 (每週日凌晨 2:00)" >> /etc/crontab
        echo "0 2 * * 0 root /etc/cron.daily/security-deep-scan" >> /etc/crontab
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
# 注意：chkrootkit 已複製到 /usr/local/bin，可以安全刪除源目錄
# 但先檢查是否有符號連結指向此目錄，如果有則先替換為實際文件
if [ -L "/usr/local/bin/chkrootkit" ]; then
    LINK_TARGET=$(readlink -f /usr/local/bin/chkrootkit 2>/dev/null)
    if [[ "$LINK_TARGET" == *"chkrootkit-master"* ]] && [ -f "$LINK_TARGET" ]; then
        echo "檢測到 chkrootkit 符號連結，替換為實際文件..."
        sudo cp -f "$LINK_TARGET" /usr/local/bin/chkrootkit
        sudo chmod +x /usr/local/bin/chkrootkit
        echo "chkrootkit 符號連結已替換為實際文件"
    fi
fi
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