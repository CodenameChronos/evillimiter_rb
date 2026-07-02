# evillimiter-fixed

Fork personal de [evillimiter](https://github.com/bitbrute/evillimiter) 
con correcciones de compatibilidad para Python 3.11+ y Fedora 44.

## Cambios respecto al original
- Resolución de nombres por DNS, NetBIOS y mDNS
- Lookup de fabricante por MAC address
- Supresión de warnings de scapy y pkg_resources

## Requisitos
- Python 3.11
- Fedora 40+ / cualquier distro con DNF o APT

## Instalación en Fedora

### 1. Dependencias del sistema
sudo dnf install python3.11 python3.11-devel iproute-tc samba-client avahi-tools

### 2. Entorno virtual
python3.11 -m venv ~/venv_evil
source ~/venv_evil/bin/activate

### 3. Dependencias Python
pip install colorama netaddr tqdm scapy terminaltables netifaces-plus mac-vendor-lookup

### 4. Instalar
sudo pip install -e . --break-system-packages

## Uso
sudo evillimiter --flush

## Fix WiFi Intel 8265 (iwlwifi) - reconexiones frecuentes
sudo nano /etc/modprobe.d/iwlwifi.conf

# Agregar:
options iwlwifi power_save=0 uapsd_disable=1
options iwlmvm power_scheme=1

## Créditos
- Original: [bitbrute](https://github.com/bitbrute/evillimiter)
- Licencia: MIT
