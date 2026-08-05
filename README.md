# stunnel SSH VPN Installer

Bu depo, Ubuntu 18.04 / 20.04 / 22.04 / 24.04 üzerinde çalışan bir SSH+Stunnel+WebSocket VPN kurulum scripti içerir (vpn.sh).

Önemli: Bu script sistem yapılandırmalarını (OpenSSH, Dropbear, stunnel4, ufw, fail2ban, systemd servisleri vb.) otomatik olarak değiştirir. Script'i yalnızca güvenilir kaynaklardan çalıştırın ve sunucunuzun yedeğini alın.

## Gereksinimler

- Root (sudo) erişimi
- Desteklenen işletim sistemleri: Ubuntu 18.04 / 20.04 / 22.04 / 24.04

## Hızlı kurulum (tek satır)

Aşağıdaki komut vpn.sh dosyasını indirip çalıştırır ve tam kurulum modunda (non-interactive değil, script kendi içinde --install seçeneğini destekler) çalıştırır:

sudo curl -fsSL https://raw.githubusercontent.com/MaydayTR38/stunnel/main/vpn.sh -o /usr/local/bin/ssh-vpn-installer.sh && sudo chmod +x /usr/local/bin/ssh-vpn-installer.sh && sudo /usr/local/bin/ssh-vpn-installer.sh --install

Bu komut:
- vpn.sh'i /usr/local/bin/ssh-vpn-installer.sh olarak kaydeder
- Çalıştırılabilir yapar
- Script'i --install ile başlatarak tam kurulum adımlarını çalıştırır

Alternatif (interaktif):

1. Dosyayı indirip çalıştırın:

sudo curl -fsSL https://raw.githubusercontent.com/MaydayTR38/stunnel/main/vpn.sh -o /usr/local/bin/ssh-vpn-installer.sh
sudo chmod +x /usr/local/bin/ssh-vpn-installer.sh
sudo /usr/local/bin/ssh-vpn-installer.sh

2. Script ilk çalıştırıldığında, kendisini /usr/local/bin/ssh-vpn ve /usr/local/bin/ssh-vpn-installer.sh olarak kopyalayacaktır, böylece daha sonra interaktif menüye `sudo ssh-vpn` komutu ile ulaşabilirsiniz.

## Kullanım

- Tam otomatik kurulum (tek satırda):
  sudo /usr/local/bin/ssh-vpn-installer.sh --install

- Interaktif menüyü başlatmak:
  sudo ssh-vpn

- Script güncelleme (script içinde tanımlı update URL):
  Script kendisini güncelleme özelliğine sahiptir; interaktif menüde "Scripti Güncelle" seçeneğini kullanabilirsiniz.

## Güvenlik ve uyarılar

- Bu script birçok servis ve yapılandırma dosyasını değiştirir; canlı üretim sunucularında kullanmadan önce test ortamında denemeniz şiddetle tavsiye edilir.
- Uzaktan indirilen ve doğrudan çalıştırılan scriptler güvenlik riski içerir. İçeriği incelemeden çalıştırmayın.

## Kaynak

- Script: https://github.com/MaydayTR38/stunnel/blob/main/vpn.sh

