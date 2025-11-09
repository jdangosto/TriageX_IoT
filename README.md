# TriageX_IoT
`TriageX_IoT` is an automated **forensic triage and evidence-collection tool** for IoT devices based on **OpenWrt**, such as [OWASP IoTGoat](https://github.com/OWASP/IoTGoat).   Written in **bash + python**, it extracts key artifacts, detects persistence mechanisms, exposed services, and vulnerabilities in LuCI or custom web panels.
# 🧠 TriageX_IoT – Forensic Triage for OpenWrt / IoT Devices

**Author:** Jesús D. Angosto (@jdangosto)  
**Version:** 1.0.0 (Educational / 2025)

---

## 📌 Overview

`TriageX_IoT` is an automated **forensic triage and evidence-collection tool** for IoT devices based on **OpenWrt**, such as [OWASP IoTGoat](https://github.com/OWASP/IoTGoat).  
Written in **bash + python**, it extracts key artifacts, detects persistence mechanisms, exposed services, and vulnerabilities in LuCI or custom web panels.

---

### 🔍 Main Features
- SSH / Dropbear fingerprint and user enumeration  
- Persistence detection (`rc.d`, `uci-defaults`, `keep.d`, `hotplug`)  
- Extraction of UCI configs (`network`, `firewall`, `uhttpd`, `dnsmasq`, `upnpd`, etc.)  
- LuCI panel inspection and dangerous function discovery (`os.execute`, `io.popen`, …)  
- SQLite database enumeration  
- SSH brute-force correlation  
- Auto-generated **Markdown forensic report** + quick text summary  

---

## ⚙️ Requirements
- **Linux** (Ubuntu, Kali, Parrot, Debian ≥ 11)
- Packages:
  ```bash
  sudo apt update
  sudo apt install -y bash coreutils findutils rsync sqlite3 python3 dropbear-bin \
                    tar gzip grep qemu-utils libguestfs-tools squashfs-tools


## 🚀 Usage
sudo mkdir -p /mnt/iotgoat_ro
sudo guestmount -a IoTGoat-x86.vmdk -i --ro /mnt/iotgoat_ro/

## Run the triage 
sudo ./triageX_iot.sh /mnt/iotgoat_ro /mnt/forensics/iot_evidences

## 📂 Output Strcuture
```
  iot_evidences/
  ├── auth/
  │   └── dropbear_fingerprint.txt
  ├── etc_full/
  ├── persistence/
  ├── network_configs/
  ├── luci_artifacts/
  │   ├── luci_manifest.csv
  │   ├── suspicious_lua.txt
  │   └── luci_iotgoat_analysis.txt
  ├── opkg_status
  ├── opkg_anomalies.txt
  ├── summary_report.txt
  ├── forensic_report.md
  └── iot_evidences.tar.gz

## 🧩 Modules and Artifacts
| Module                        | Collected Evidence                                         |
| ----------------------------- | ---------------------------------------------------------- |
| **Authentication / Dropbear** | `/etc/passwd`, `/etc/shadow`, SHA-256 host-key fingerprint |
| **Persistence**               | `rc.d`, `uci-defaults`, `rc.local`, `keep.d`, `hotplug.d`  |
| **Networking / Services**     | `uHTTPd`, `firewall`, `dnsmasq`, `upnpd`, `miniupnpd`      |
| **LuCI / IoTGoat panel**      | Lua controllers, views, sessions, risky functions          |
| **Packages / Firmware**       | `opkg_status`, `opkg_anomalies.txt`                        |
| **Logs / Temp Data**          | `/var/log`, `/tmp`, `/run` (copied + decompressed)         |
| **IoCs**                      | IPs, domains, credentials, command traces                  |
| **SQLite DBs**                | Table listing and sample content                           |
| **SSH Brute-Force Analysis**  | `ssh_events.txt`, `ssh_bruteforce_summary.csv`             |

## 🧾 Key Files
| File                          | Description                            |
| ----------------------------- | -------------------------------------- |
| `triageX_iot.sh`              | Main script                            |
| `forensic_report.md`          | Structured DFIR report (Markdown)      |
| `summary_report.txt`          | Quick summary of findings              |
| `run.log`                     | Execution log for debug / traceability |

## 🧰 Example Run
$ sudo ./triageX_IOT.sh /mnt/iotgoat_ro iot_evidences



