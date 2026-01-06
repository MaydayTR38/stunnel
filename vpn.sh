#!/bin/bash

# ═══════════════════════════════════════════════════════════════
# SSH VPN INSTALLER - HTTP Injector & HTTP Custom Uyumlu
# Ubuntu 18.04 / 20.04 / 22.04 / 24.04
# ═══════════════════════════════════════════════════════════════

# Renk Tanımlamaları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Değişkenler
DROPBEAR_PORT=442
SSH_PORT=22
SSL_PORT=443
WS_PORT=80
OPENSSH_SSL_PORT=444

# Root kontrolü
check_root() {
if [[ $EUID -ne 0 ]]; then
echo -e "${RED}Bu script root olarak çalıştırılmalı!${NC}"
echo -e "${YELLOW}Kullanım: sudo $0${NC}"
exit 1
fi
}

# Banner
show_banner() {
clear
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║ ║"
echo "║ ███████╗███████╗██╗ ██╗ ██╗ ██╗██████╗ ███╗ ██╗ ║"
echo "║ ██╔════╝██╔════╝██║ ██║ ██║ ██║██╔══██╗████╗ ██║ ║"
echo "║ ███████╗███████╗███████║ ██║ ██║██████╔╝██╔██╗ ██║ ║"
echo "║ ╚════██║╚════██║██╔══██║ ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║ ║"
echo "║ ███████║███████║██║ ██║ ╚████╔╝ ██║ ██║ ╚████║ ║"
echo "║ ╚══════╝╚══════╝╚═╝ ╚═╝ ╚═══╝ ╚═╝ ╚═╝ ╚═══╝ ║"
echo "║ ║"
echo "║ HTTP Injector & HTTP Custom Uyumlu ║"
echo "║ SSL/TLS VPN Installer ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
}

# Sistem bilgisi
show_system_info() {
IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "Bilinmiyor")
OS=$(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
KERNEL=$(uname -r)
RAM=$(free -m | awk 'NR==2{printf "%.1fGB", $2/1024}')
CPU=$(nproc)

echo -e "${WHITE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${WHITE}║${NC} ${YELLOW}Sunucu IP:${NC} $IP"
echo -e "${WHITE}║${NC} ${YELLOW}İşletim Sistemi:${NC} $OS"
echo -e "${WHITE}║${NC} ${YELLOW}Kernel:${NC} $KERNEL"
echo -e "${WHITE}║${NC} ${YELLOW}RAM:${NC} $RAM | ${YELLOW}CPU:${NC} $CPU Core"
echo -e "${WHITE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
}

# İlerleme çubuğu
progress_bar() {
local duration=$1
local prefix=$2
local size=40
local progress=0

while [ $progress -le 100 ]; do
local count=$((progress * size / 100))
local spaces=$((size - count))
printf "\r${prefix} [${GREEN}"
printf "%${count}s" | tr ' ' '█'
printf "${NC}%${spaces}s] ${progress}%%" | tr ' ' '░'
progress=$((progress + 2))
sleep $duration
done
echo ""
}

# Sistem güncelleme
update_system() {
echo -e "\n${YELLOW}[1/8] Sistem güncelleniyor...${NC}"
apt update -y > /dev/null 2>&1
apt upgrade -y > /dev/null 2>&1
progress_bar 0.02 "Güncelleme"
echo -e "${GREEN}✓ Sistem güncellendi${NC}"
}

# Paket kurulumu
install_packages() {
echo -e "\n${YELLOW}[2/8] Gerekli paketler kuruluyor...${NC}"

# /bin/false'i shells dosyasına ekle (Dropbear auth hatası için)
if ! grep -q "/bin/false" /etc/shells; then
echo "/bin/false" >> /etc/shells
fi

PACKAGES="wget curl openssl stunnel4 dropbear openssh-server python3 net-tools ufw fail2ban lsb-release"

for pkg in $PACKAGES; do
apt install -y $pkg > /dev/null 2>&1
echo -e " ${GREEN}✓${NC} $pkg"
done

echo -e "${GREEN}✓ Tüm paketler kuruldu${NC}"
}

# OpenSSH yapılandırması
configure_openssh() {
echo -e "\n${YELLOW}[3/8] OpenSSH yapılandırılıyor...${NC}"

# Yedek al
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config << EOF
# SSH VPN Configuration
Port $SSH_PORT
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# VPN Optimizasyonları
AllowTcpForwarding yes
GatewayPorts yes
TCPKeepAlive yes
ClientAliveInterval 30
ClientAliveCountMax 99999
UseDNS no
MaxSessions 100
EOF

systemctl restart sshd
systemctl enable sshd > /dev/null 2>&1

echo -e "${GREEN}✓ OpenSSH yapılandırıldı (Port: $SSH_PORT)${NC}"
}

# Dropbear yapılandırması
configure_dropbear() {
echo -e "\n${YELLOW}[4/8] Dropbear yapılandırılıyor...${NC}"

cat > /etc/default/dropbear << EOF
# Dropbear SSH Configuration
NO_START=0
DROPBEAR_PORT=$DROPBEAR_PORT
DROPBEAR_EXTRA_ARGS="-p $DROPBEAR_PORT"
DROPBEAR_BANNER=""
DROPBEAR_RECEIVE_WINDOW=65536
EOF

systemctl restart dropbear
systemctl enable dropbear > /dev/null 2>&1

echo -e "${GREEN}✓ Dropbear yapılandırıldı (Port: $DROPBEAR_PORT)${NC}"
}

# SSL Sertifikası oluşturma
create_ssl_certificate() {
echo -e "\n${YELLOW}[5/8] SSL Sertifikası oluşturuluyor...${NC}"

mkdir -p /etc/stunnel

# Self-signed sertifika oluştur
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
-subj "/C=TR/ST=Istanbul/L=Istanbul/O=VPN-Server/OU=SSL/CN=vpn-server" \
-keyout /etc/stunnel/stunnel.key \
-out /etc/stunnel/stunnel.crt > /dev/null 2>&1

cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt > /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.pem

echo -e "${GREEN}✓ SSL Sertifikası oluşturuldu${NC}"
}

# Stunnel yapılandırması
configure_stunnel() {
echo -e "\n${YELLOW}[6/8] Stunnel (SSL/TLS) yapılandırılıyor...${NC}"

cat > /etc/stunnel/stunnel.conf << EOF
# Stunnel SSL Configuration
pid = /var/run/stunnel4/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

# Dropbear üzerinden SSL (Port 443)
[dropbear-ssl]
accept = $SSL_PORT
connect = 127.0.0.1:$DROPBEAR_PORT

# OpenSSH üzerinden SSL (Port 444)
[openssh-ssl]
accept = $OPENSSH_SSL_PORT
connect = 127.0.0.1:$SSH_PORT
EOF

# Stunnel'ı etkinleştir
sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4

# Stunnel PID dizini oluştur
mkdir -p /var/run/stunnel4
chown stunnel4:stunnel4 /var/run/stunnel4

systemctl restart stunnel4
systemctl enable stunnel4 > /dev/null 2>&1

echo -e "${GREEN}✓ Stunnel yapılandırıldı (SSL Port: $SSL_PORT)${NC}"
}

# WebSocket Proxy kurulumu
install_websocket() {
echo -e "\n${YELLOW}[7/8] WebSocket Proxy kuruluyor...${NC}"

# WebSocket Python scripti
cat > /usr/local/bin/ws-proxy.py << 'WSEOF'
#!/usr/bin/env python3
"""
WebSocket SSH Proxy
HTTP Injector & HTTP Custom uyumlu
"""

import socket
import threading
import sys
import select
import signal

# Yapılandırma
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 80
SSH_HOST = '127.0.0.1'
SSH_PORT = 22
BUFFER_SIZE = 65535

active_connections = 0
lock = threading.Lock()

def log(message):
    print(f"[WS-PROXY] {message}")

def handle_client(client_socket, client_address):
    global active_connections

    with lock:
        active_connections += 1

    try:
        # HTTP isteğini al
        request = client_socket.recv(BUFFER_SIZE)

        if not request:
            return

        request_str = request.decode('utf-8', errors='ignore')

        # HTTP CONNECT veya normal HTTP isteği kontrolü
        if 'CONNECT' in request_str or 'GET' in request_str or 'HTTP' in request_str:
            # HTTP 200 OK yanıtı gönder
            response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
            client_socket.send(response)

            # SSH sunucusuna bağlan
            ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            ssh_socket.settimeout(30)

            try:
                ssh_socket.connect((SSH_HOST, SSH_PORT))
            except Exception as e:
                log(f"SSH bağlantı hatası: {e}")
                return

            # İki yönlü veri transferi
            client_socket.setblocking(0)
            ssh_socket.setblocking(0)

            while True:
                try:
                    readable, _, exceptional = select.select(
                        [client_socket, ssh_socket], [],
                        [client_socket, ssh_socket], 30
                    )

                    if exceptional:
                        break

                    for sock in readable:
                        if sock is client_socket:
                            data = client_socket.recv(BUFFER_SIZE)
                            if not data:
                                raise Exception("Client disconnected")
                            ssh_socket.send(data)
                        elif sock is ssh_socket:
                            data = ssh_socket.recv(BUFFER_SIZE)
                            if not data:
                                raise Exception("SSH disconnected")
                            client_socket.send(data)

                except Exception:
                    break

            try:
                ssh_socket.close()
            except:
                pass

    except Exception as e:
        pass
    finally:
        with lock:
            active_connections -= 1
        try:
            client_socket.close()
        except:
            pass

def signal_handler(signum, frame):
    log("Kapatılıyor...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    try:
        server.bind((LISTEN_HOST, LISTEN_PORT))
        server.listen(100)
        log(f"WebSocket Proxy başlatıldı - Port: {LISTEN_PORT}")
        log(f"SSH Hedef: {SSH_HOST}:{SSH_PORT}")

        while True:
            try:
                client, address = server.accept()
                thread = threading.Thread(
                    target=handle_client,
                    args=(client, address),
                    daemon=True
                )
                thread.start()
            except Exception as e:
                log(f"Bağlantı hatası: {e}")

    except Exception as e:
        log(f"Sunucu hatası: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
WSEOF

chmod +x /usr/local/bin/ws-proxy.py

# Systemd servisi oluştur
cat > /etc/systemd/system/ws-proxy.service << EOF
[Unit]
Description=WebSocket SSH Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/ws-proxy.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start ws-proxy
systemctl enable ws-proxy > /dev/null 2>&1

echo -e "${GREEN}✓ WebSocket Proxy kuruldu (Port: $WS_PORT)${NC}"
}

# Güvenlik duvarı yapılandırması
configure_firewall() {
echo -e "\n${YELLOW}[8/8] Güvenlik duvarı yapılandırılıyor...${NC}"

# UFW kuralları
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

ufw allow $SSH_PORT/tcp > /dev/null 2>&1
ufw allow $WS_PORT/tcp > /dev/null 2>&1
ufw allow $DROPBEAR_PORT/tcp > /dev/null 2>&1
ufw allow $SSL_PORT/tcp > /dev/null 2>&1
ufw allow $OPENSSH_SSL_PORT/tcp > /dev/null 2>&1

echo "y" | ufw enable > /dev/null 2>&1

echo -e "${GREEN}✓ Güvenlik duvarı yapılandırıldı${NC}"
}

# BBR optimizasyonu
enable_bbr() {
echo -e "\n${YELLOW}BBR Congestion Control aktifleştiriliyor...${NC}"

cat >> /etc/sysctl.conf << EOF

# BBR Congestion Control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Network Optimizasyonları
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=1200
net.ipv4.ip_local_port_range=10000 65000
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets=5000
net.core.somaxconn=4096
net.core.netdev_max_backlog=4096
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
EOF

sysctl -p > /dev/null 2>&1

echo -e "${GREEN}✓ BBR aktifleştirildi${NC}"
}

# Kullanıcı oluşturma
create_user() {
echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE} YENİ VPN KULLANICISI OLUŞTUR${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

read -p "Kullanıcı adı: " username

if id "$username" &>/dev/null; then
echo -e "${RED}Bu kullanıcı zaten mevcut!${NC}"
return
fi

read -sp "Şifre: " password
echo ""
read -p "Hesap süresi (gün, 0=sınırsız): " days

# Kullanıcı oluştur
useradd -m -s /bin/false "$username"
echo "$username:$password" | chpasswd

# Süre belirle
if [[ "$days" != "0" && "$days" != "" ]]; then
expire_date=$(date -d "+${days} days" +%Y-%m-%d)
chage -E "$expire_date" "$username"
echo -e "\n${GREEN}✓ Kullanıcı oluşturuldu${NC}"
echo -e " Bitiş tarihi: $expire_date"
else
echo -e "\n${GREEN}✓ Kullanıcı oluşturuldu (Sınırsız)${NC}"
fi

IP=$(curl -s ifconfig.me 2>/dev/null)

echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE} BAĞLANTI BİLGİLERİ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e " ${YELLOW}Sunucu:${NC} $IP"
echo -e " ${YELLOW}SSH Port:${NC} $SSH_PORT"
echo -e " ${YELLOW}SSL Port:${NC} $SSL_PORT"
echo -e " ${YELLOW}WS Port:${NC} $WS_PORT"
echo -e " ${YELLOW}Kullanıcı:${NC} $username"
echo -e " ${YELLOW}Şifre:${NC} $password"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

# Kullanıcı silme
delete_user() {
echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE} VPN KULLANICISI SİL${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

# Kullanıcı listesi
echo -e "${YELLOW}Mevcut kullanıcılar:${NC}"
awk -F: '$3 >= 1000 && $1 != "nobody" {print " - " $1}' /etc/passwd
echo ""

read -p "Silinecek kullanıcı adı: " username

if id "$username" &>/dev/null; then
userdel -r "$username" 2>/dev/null
echo -e "${GREEN}✓ Kullanıcı silindi: $username${NC}"
else
echo -e "${RED}Kullanıcı bulunamadı!${NC}"
fi
}

# Kullanıcı listesi
list_users() {
echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE} VPN KULLANICI LİSTESİ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

printf "%-20s %-15s %-20s\n" "KULLANICI" "DURUM" "BİTİŞ TARİHİ"
echo "─────────────────────────────────────────────────────────────"

while IFS=: read -r username _ uid _; do
if [[ $uid -ge 1000 && "$username" != "nobody" ]]; then
expire=$(chage -l "$username" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)

if [[ "$expire" == "never" ]]; then
status="${GREEN}Aktif${NC}"
expire="Sınırsız"
else
exp_date=$(date -d "$expire" +%s 2>/dev/null)
now=$(date +%s)

if [[ $exp_date -gt $now ]]; then
status="${GREEN}Aktif${NC}"
else
status="${RED}Süresi Dolmuş${NC}"
fi
fi

printf "%-20s %-15b %-20s\n" "$username" "$status" "$expire"
fi
done < /etc/passwd

echo ""
}

# Servis durumu
service_status() {
echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE} SERVİS DURUMU${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

services=("sshd" "dropbear" "stunnel4" "ws-proxy")

for service in "${services[@]}"; do
if systemctl is-active --quiet "$service"; then
status="${GREEN}● Çalışıyor${NC}"
else
status="${RED}● Durdu${NC}"
fi
printf " %-15s %b\n" "$service" "$status"
done

echo -e "\n${YELLOW}Açık Portlar:${NC}"
echo "─────────────────────────────────────────────────────────────"
netstat -tlnp 2>/dev/null | grep -E "($SSH_PORT|$WS_PORT|$DROPBEAR_PORT|$SSL_PORT|$OPENSSH_SSL_PORT)" | \
awk '{printf " Port %-6s %s\n", $4, $7}'
echo ""
}

# Servisleri yeniden başlat
restart_services() {
echo -e "\n${YELLOW}Servisler yeniden başlatılıyor...${NC}"

systemctl restart sshd
systemctl restart dropbear
systemctl restart stunnel4
systemctl restart ws-proxy

echo -e "${GREEN}✓ Tüm servisler yeniden başlatıldı${NC}"
}

# Bağlantı bilgileri
show_connection_info() {
IP=$(curl -s ifconfig.me 2>/dev/null || echo "Bilinmiyor")

echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE} HTTP INJECTOR / HTTP CUSTOM AYARLARI${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

echo -e "${YELLOW}▸ SSL/TLS Bağlantısı (Port 443):${NC}"
echo -e " Host: $IP"
echo -e " Port: $SSL_PORT"
echo -e " SSL: Açık"
echo -e " SNI: [operatör-host]"

echo -e "\n${YELLOW}▸ WebSocket Bağlantısı (Port 80):${NC}"
echo -e " Host: $IP"
echo -e " Port: $WS_PORT"
echo -e " Payload: GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]"

echo -e "\n${YELLOW}▸ Direkt SSH Bağlantısı:${NC}"
echo -e " Host: $IP"
echo -e " SSH Port: $SSH_PORT"
echo -e " Dropbear Port: $DROPBEAR_PORT"

echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE} ÖRNEK PAYLOAD AYARLARI${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

cat << 'EOF'
▸ HTTP Injector Payload:
GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]

▸ HTTP Custom Payload:
CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]
EOF

echo ""
}

# Script'i kaldır
uninstall() {
echo -e "\n${RED}DİKKAT: Tüm VPN yapılandırması silinecek!${NC}"
read -p "Devam etmek istiyor musunuz? (e/h): " confirm

if [[ "$confirm" != "e" && "$confirm" != "E" ]]; then
echo -e "${YELLOW}İptal edildi.${NC}"
return
fi

echo -e "\n${YELLOW}Kaldırılıyor...${NC}"

systemctl stop ws-proxy 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop dropbear 2>/dev/null

systemctl disable ws-proxy 2>/dev/null
systemctl disable stunnel4 2>/dev/null
systemctl disable dropbear 2>/dev/null

rm -f /etc/systemd/system/ws-proxy.service
rm -f /usr/local/bin/ws-proxy.py
rm -rf /etc/stunnel

apt remove -y dropbear stunnel4 > /dev/null 2>&1

systemctl daemon-reload

echo -e "${GREEN}✓ VPN yapılandırması kaldırıldı${NC}"
}

# Tam kurulum
full_install() {
show_banner
show_system_info

echo -e "${WHITE}Tam kurulum başlatılıyor...${NC}\n"
sleep 2

update_system
install_packages
configure_openssh
configure_dropbear
create_ssl_certificate
configure_stunnel
install_websocket
install_badvpn
configure_firewall
enable_bbr

echo -e "\n${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN} ✓ KURULUM BAŞARIYLA TAMAMLANDI!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"

show_connection_info

echo -e "${YELLOW}Kullanıcı oluşturmak için 'ssh-vpn' komutunu çalıştırın.${NC}\n"
}

# BadVPN kurulumu (UDP Desteği)
install_badvpn() {
echo -e "\n${YELLOW}[Ek] BadVPN (UDP Desteği) kuruluyor...${NC}"

wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64" > /dev/null 2>&1
chmod +x /usr/bin/badvpn-udpgw

cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
User=root
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start badvpn
systemctl enable badvpn > /dev/null 2>&1

echo -e "${GREEN}✓ BadVPN kuruldu (UDP Gateway Port: 7300)${NC}"
}

# Online kullanıcıları göster
show_online_users() {
echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE} ONLINE KULLANICILAR${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

printf "%-20s %-15s %-10s\n" "KULLANICI" "DURUM" "PID"
echo "─────────────────────────────────────────────────────────────"

found=0
while IFS=: read -r username _ uid _; do
if [[ $uid -ge 1000 && "$username" != "nobody" ]]; then
if pgrep -u "$username" > /dev/null 2>&1; then
pids=$(pgrep -u "$username" | head -n 1) # İlk PID'yi al
printf "%-20s %-15b %-10s\n" "$username" "${GREEN}● Çevrimiçi${NC}" "$pids"
found=1
fi
fi
done < /etc/passwd

if [[ $found -eq 0 ]]; then
echo -e "${YELLOW}Şu an bağlı kullanıcı yok.${NC}"
fi
echo ""
}

# Oto-Reboot yapılandırması
configure_autoreboot() {
echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE} OTO-REBOOT AYARLARI${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

echo -e "Sunucunun her gece 00:00'da otomatik yeniden başlatılması"
echo -e "performansı korur ve RAM şişmesini önler.\n"

if [ -f /etc/cron.d/vpn_autoreboot ]; then
echo -e "Mevcut Durum: ${GREEN}AKTİF${NC}"
else
echo -e "Mevcut Durum: ${RED}PASİF${NC}"
fi
echo ""

read -p "Oto-Reboot durumu değiştirilsin mi? (e/h): " choice

if [[ "$choice" == "e" || "$choice" == "E" ]]; then
if [ -f /etc/cron.d/vpn_autoreboot ]; then
rm -f /etc/cron.d/vpn_autoreboot
echo -e "\n${YELLOW}Oto-Reboot iptal edildi.${NC}"
else
echo "0 0 * * * root /sbin/reboot" > /etc/cron.d/vpn_autoreboot
service cron restart > /dev/null 2>&1
echo -e "\n${GREEN}✓ Oto-Reboot aktif edildi (Her gece 00:00)${NC}"
fi
fi
}

# Hız Testi
run_speedtest() {
echo -e "\n${YELLOW}Hız testi başlatılıyor...${NC}"
echo -e "Lütfen bekleyin, bu işlem biraz sürebilir.\n"

if ! command -v speedtest-cli &> /dev/null; then
echo -e "Speedtest aracı kuruluyor..."
apt install speedtest-cli -y > /dev/null 2>&1
fi

speedtest-cli --simple
echo ""
}

# Sistem Temizliği
clean_system() {
echo -e "\n${YELLOW}Sistem temizleniyor...${NC}"

# RAM Cache Temizliği
sync; echo 3 > /proc/sys/vm/drop_caches
echo -e " ${GREEN}✓${NC} RAM Önbelleği temizlendi"

# Swap Temizliği
swapoff -a && swapon -a 2>/dev/null
echo -e " ${GREEN}✓${NC} Swap alanı temizlendi"

# Log Temizliği
journalctl --vacuum-time=1d > /dev/null 2>&1
rm -rf /var/log/*.gz > /dev/null 2>&1
echo -e " ${GREEN}✓${NC} Eski loglar temizlendi"

# Paket Önbelleği
apt autoremove -y > /dev/null 2>&1
apt clean -y > /dev/null 2>&1
echo -e " ${GREEN}✓${NC} Paket artıkları temizlendi"

echo -e "\n${GREEN}Temizlik tamamlandı!${NC}\n"
}

# Ana menü
main_menu() {
while true; do
show_banner
show_system_info

echo -e "${WHITE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${WHITE}║${NC} ${YELLOW}ANA MENÜ${NC} ${WHITE}║${NC}"
echo -e "${WHITE}╠═══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[1]${NC} Tam Kurulum (İlk Kurulum) ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[2]${NC} Kullanıcı Oluştur ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[3]${NC} Kullanıcı Sil ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[4]${NC} Kullanıcı Listesi ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[5]${NC} Online Kullanıcılar ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[6]${NC} Servis Durumu ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[7]${NC} Servisleri Yeniden Başlat ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[8]${NC} Bağlantı Bilgileri ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[9]${NC} BBR Aktifleştir ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[10]${NC} Oto-Reboot Ayarı ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[11]${NC} Sunucu Hız Testi ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${GREEN}[12]${NC} Sistem Temizliği (RAM/Log) ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${RED}[13]${NC} Kaldır ${WHITE}║${NC}"
echo -e "${WHITE}║${NC} ${PURPLE}[0]${NC} Çıkış ${WHITE}║${NC}"
echo -e "${WHITE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
read -p "Seçiminiz [0-13]: " choice

case $choice in
1) full_install; read -p "Devam etmek için Enter'a basın..." ;;
2) create_user; read -p "Devam etmek için Enter'a basın..." ;;
3) delete_user; read -p "Devam etmek için Enter'a basın..." ;;
4) list_users; read -p "Devam etmek için Enter'a basın..." ;;
5) show_online_users; read -p "Devam etmek için Enter'a basın..." ;;
6) service_status; read -p "Devam etmek için Enter'a basın..." ;;
7) restart_services; read -p "Devam etmek için Enter'a basın..." ;;
8) show_connection_info; read -p "Devam etmek için Enter'a basın..." ;;
9) enable_bbr; read -p "Devam etmek için Enter'a basın..." ;;
10) configure_autoreboot; read -p "Devam etmek için Enter'a basın..." ;;
11) run_speedtest; read -p "Devam etmek için Enter'a basın..." ;;
12) clean_system; read -p "Devam etmek için Enter'a basın..." ;;
13) uninstall; read -p "Devam etmek için Enter'a basın..." ;;
0) echo -e "\n${GREEN}Görüşmek üzere!${NC}\n"; exit 0 ;;
*) echo -e "${RED}Geçersiz seçim!${NC}"; sleep 1 ;;
esac
done
}

# Script'i global komut olarak ekle
create_command() {
cp "$0" /usr/local/bin/ssh-vpn-installer.sh 2>/dev/null
chmod +x /usr/local/bin/ssh-vpn-installer.sh 2>/dev/null
ln -sf /usr/local/bin/ssh-vpn-installer.sh /usr/local/bin/ssh-vpn 2>/dev/null
}

# Ana fonksiyon
main() {
check_root
create_command

if [[ "$1" == "--install" || "$1" == "-i" ]]; then
full_install
else
main_menu
fi
}

# Script'i başlat
main "$@"
