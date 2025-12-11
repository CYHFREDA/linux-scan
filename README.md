# Security Monitor v3.5 - Linux 安全監控系統

一個輕量、全面、即時的 Linux 伺服器安全監控系統，整合多種安全工具並提供 Telegram 即時通知。

## 📋 功能特色

### 🔴 即時威脅偵測
- **Reverse Shell 偵測**：每 60 秒檢查可疑的 reverse shell 連接
- **高 CPU 使用監控**：每 5 分鐘檢查，CPU > 70% 時發送警告
- **Port Scan 偵測**：偵測異常連線數（> 20 個連接）
- **敏感檔案監控**：即時監控 `/etc/passwd`、`/etc/shadow`、`/etc/sudoers`、`/etc/ssh/sshd_config` 的變更

### 📊 每日安全報告
每天早上 6:30 自動執行，包含：
- 系統資源狀態（CPU、記憶體、磁碟）
- 安全事件統計（登入記錄、Fail2ban 封鎖、Audit 事件）
- 威脅掃描結果（病毒、Rootkit、惡意軟體）
- 系統維護資訊（安全更新、檔案變動）
- 自動發送 Telegram 通知

### 🔍 深度安全掃描
每天凌晨 2:00 自動執行，包含：
- **Lynis**：系統安全審計
- **chkrootkit**：Rootkit 檢測
- **Maldet (LMD)**：惡意軟體掃描
- **ClamAV**：病毒掃描（重點目錄：/home, /root, /opt, /var/www, /tmp, /var/tmp, /srv/data, /data, /backup）
- **AIDE**：檔案完整性檢查
- 自動發送 Telegram 通知

#### 📁 掃描目錄說明
- **每日檢查**：掃描 `/home`, `/root`, `/opt`, `/var/www`, `/srv/data`, `/data`, `/backup`
- **深度掃描**：掃描 `/home`, `/root`, `/opt`, `/var/www`, `/tmp`, `/var/tmp`, `/srv/data`, `/data`, `/backup`

**為什麼不掃描系統目錄（/usr, /bin, /sbin 等）？**
- 系統目錄由套件管理器管理，有完整性檢查（RPM 驗證）
- 掃描系統目錄會非常耗時（數小時），且效益低
- 病毒和惡意軟體通常出現在用戶數據目錄，而非系統目錄
- 如需完整掃描，可手動執行：`clamscan -r /`

### 📱 Telegram 即時通知
- 安裝完成通知
- 即時威脅警告
- 每日安全報告
- 深度掃描報告

## 🛠 安裝的安全工具

| 工具 | 用途 | 說明 |
|------|------|------|
| **Fail2ban** | 入侵防護 | 自動封鎖暴力破解 IP |
| **ClamAV** | 防毒軟體 | 病毒掃描與檢測 |
| **Lynis** | 安全審計 | 系統安全評估與建議 |
| **chkrootkit** | Rootkit 檢測 | 檢測隱藏的 Rootkit |
| **Maldet (LMD)** | 惡意軟體掃描 | Linux 惡意軟體檢測 |
| **AIDE** | 檔案完整性 | 監控系統檔案變更 |
| **rkhunter** | Rootkit 檢測 | 另一款 Rootkit 檢測工具 |
| **audit** | 系統審計 | 記錄系統活動 |

## 📦 系統需求

- **作業系統**：Rocky Linux 9 / RHEL 9 / CentOS Stream 9
- **權限**：需要 root 權限
- **網路**：需要網路連線下載工具和發送 Telegram 通知
- **磁碟空間**：建議至少 2GB 可用空間（用於日誌和病毒庫）

## 🚀 快速安裝

```bash
# 下載腳本
git clone https://github.com/CYHFREDA/linux-scan.git
cd linux-scan

# 執行安裝（需要 root 權限）
sudo bash install-security-monitor.sh
```

## ⚙️ 配置 Telegram 通知

安裝腳本會自動創建 Telegram 配置檔，如需修改：

```bash
# 編輯 Telegram 設定
vi /opt/security/config/telegram.token
```

設定內容：
```bash
TG_BOT_TOKEN="你的 Bot Token"
TG_CHAT_ID="你的 Chat ID"
```

### 如何取得 Telegram Bot Token 和 Chat ID？

1. **建立 Bot**：
   - 在 Telegram 搜尋 `@BotFather`
   - 發送 `/newbot` 並依照指示建立 Bot
   - 取得 Bot Token

2. **取得 Chat ID**：
   - 在 Telegram 搜尋 `@userinfobot`
   - 發送訊息取得你的 Chat ID（負數為群組 ID）

## 📁 目錄結構

```
/opt/security/
├── scripts/              # 監控腳本
│   ├── reverse-shell-detector.sh
│   ├── process-monitor.sh
│   ├── network-monitor.sh
│   ├── file-monitor.sh
│   └── send-telegram.sh
├── logs/                 # 日誌檔案
│   ├── daily-report-*.txt
│   ├── clamav-daily-*.log
│   ├── chkrootkit-*.log
│   ├── maldet-*.log
│   └── lynis-*.log
├── reports/             # 深度掃描報告
│   └── daily-*.txt
├── config/              # 設定檔
│   └── telegram.token
└── tmp/                 # 暫存檔案
```

## 🔧 服務管理

### 查看服務狀態
```bash
systemctl status reverse-shell-detector
systemctl status process-monitor
systemctl status network-monitor
systemctl status file-monitor
systemctl status clamd@scan
```

### 手動啟動/停止服務
```bash
# 啟動服務
systemctl start reverse-shell-detector
systemctl start process-monitor
systemctl start network-monitor
systemctl start file-monitor

# 停止服務
systemctl stop reverse-shell-detector
systemctl stop process-monitor
```

### 查看日誌
```bash
# 查看服務日誌
journalctl -u reverse-shell-detector -f
journalctl -u process-monitor -f

# 查看應用日誌
tail -f /opt/security/logs/reverse-shell.log
tail -f /opt/security/logs/process-monitor.log
```

## 📅 排程任務

### 每日檢查（每天早上 6:30）
```bash
# 手動執行
bash /etc/cron.daily/security-check

# 查看報告
cat /opt/security/logs/daily-report-$(date +%Y%m%d).txt
```

### 深度掃描（每天凌晨 2:00）
```bash
# 手動執行
bash /etc/cron.daily/security-deep-scan

# 查看報告
cat /opt/security/reports/daily-$(date +%F).txt
```

## 📱 Telegram 通知範例

### 每日安全報告
```
📊 每日安全報告 - 12/11
━━━━━━━━━━━━━━━━
🖥 主機: server01

💻 系統資源
├ CPU: 15% (process-name)
├ 記憶體: 2.5G/8G (31%)
└ 磁碟: 45% 使用中

🔐 安全事件
├ 登入次數: 5
├ 登入失敗: 2 次
├ 當前封鎖 IP: 3 (總計: 15)
└ 敏感檔案變動: 0

🛡 威脅掃描
├ 病毒: 0
├ Rootkit 警告: 0
└ 惡意軟體: 0

狀態: 🟢 正常
```

### 即時威脅警告
```
🔴 Reverse Shell 偵測
[連接詳情]

⚠️ High CPU Usage
process-name
CPU: 85%

🚨 Port Scan 偵測
IP: 192.168.1.100
連線數: 25

🔐 敏感檔案變更!
檔案: /etc/passwd
動作: modify
```

## 🔧 自定義掃描目錄

### 修改每日檢查掃描目錄
編輯 `/etc/cron.daily/security-check`，找到：
```bash
CLAMAV_DIRS=(/home /root /opt /var/www /srv/data /data /backup)
```
添加或移除目錄，例如：
```bash
CLAMAV_DIRS=(/home /root /opt /var/www /tmp /var/tmp /custom/path)
```

### 修改深度掃描目錄
編輯 `/etc/cron.daily/security-deep-scan`，找到：
```bash
for dir in /home /root /opt /var/www /tmp /var/tmp /srv/data /data /backup; do
```
修改為您需要的目錄。

### 完整系統掃描（不建議）
如需掃描整個系統（非常耗時，可能需要數小時）：
```bash
# 手動執行完整掃描
clamscan -r / --infected --log=/opt/security/logs/full-scan.log
```

## 🔍 故障排除

### ClamAV 更新失敗
```bash
# 手動修復權限
sudo mkdir -p /var/lib/clamav/tmp
sudo chown -R 989:988 /var/lib/clamav
sudo chmod 755 /var/lib/clamav
sudo chmod 1777 /var/lib/clamav/tmp

# 手動更新病毒庫
sudo freshclam
```

### 服務無法啟動
```bash
# 檢查服務狀態
systemctl status <服務名稱>

# 查看詳細錯誤
journalctl -u <服務名稱> -n 50

# 檢查腳本權限
ls -la /opt/security/scripts/
chmod +x /opt/security/scripts/*.sh
```

### Telegram 通知未發送
```bash
# 檢查配置檔
cat /opt/security/config/telegram.token

# 測試發送
/opt/security/scripts/send-telegram.sh "測試訊息"

# 檢查網路連線
curl -s https://api.telegram.org
```

## 🗑️ 卸載

```bash
# 停止所有服務
systemctl stop reverse-shell-detector process-monitor network-monitor file-monitor
systemctl disable reverse-shell-detector process-monitor network-monitor file-monitor

# 刪除服務檔案
rm -f /etc/systemd/system/{reverse-shell-detector,process-monitor,network-monitor,file-monitor}.service

# 刪除 crontab 項目
sed -i '/security-check/d' /etc/crontab
sed -i '/security-deep-scan/d' /etc/crontab

# 刪除腳本和日誌（可選）
rm -rf /opt/security
rm -f /etc/cron.daily/security-check
rm -f /etc/cron.daily/security-deep-scan
```

## 📝 版本歷史

### v3.5 (當前版本)
- ✅ 改進深度掃描腳本，添加進度提示
- ✅ 修復 ClamAV 權限問題
- ✅ 改進錯誤處理和日誌記錄
- ✅ 優化 Telegram 通知格式
- ✅ 添加服務狀態檢查和自動修復
---

**⚠️ 注意事項**：
- 本系統會持續監控伺服器，可能產生一定的系統負載
- 建議在測試環境先驗證後再部署到生產環境
- 定期檢查日誌檔案大小，避免佔用過多磁碟空間
- 確保 Telegram Bot Token 和 Chat ID 的安全性