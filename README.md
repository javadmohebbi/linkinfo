# linkinfo

# linkinfo

`linkinfo` is a cross‑platform command‑line tool that discovers the switch port, VLAN, system name, port description, and chassis/port identifiers of the network device your machine is connected to. It listens for **LLDP (IEEE 802.1AB)** and **CDP (Cisco Discovery Protocol)** frames and decodes all relevant TLVs, including organizational TLVs such as VLAN, Voice VLAN, tagged VLANs, and VLAN names.

Supported Platforms:
- macOS (amd64, arm64)
- Linux (386, amd64, arm, arm64)
- Windows (386, amd64)

All binaries are built via the included Makefile.

---

## ✨ Features
- Detects LLDP (0x88cc) and CDP (01:00:0c:cc:cc:cc)
- Extracts:
  - Switch system name
  - Port ID / Port Description
  - Chassis ID
  - Platform (CDP)
  - VLAN (Native VLAN or PVID)
  - Voice VLAN
  - Tagged VLAN list
  - VLAN names (TLV subtype 3)
  - Management address
- Parses organizational TLVs (IEEE 802.1, LLDP‑MED)
- Works on **Linux, macOS, and Windows**
- Uses libpcap / npcap
- Provides detailed debug output via raw TLV capture

---

## 📦 Installation

### Build from source
```bash
git clone https://github.com/javadmohebbi/linkinfo.git
cd linkinfo
make
```

Resulting binaries will appear in `./dist/`:
```
linkinfo-linux-amd64
linkinfo-linux-386
linkinfo-linux-arm
linkinfo-linux-arm64
linkinfo-darwin-amd64
linkinfo-darwin-arm64
linkinfo-windows-amd64.exe
linkinfo-windows-386.exe
```

---

## 🔧 Usage

### List all interfaces
```bash
linkinfo -list
```

### Capture LLDP/CDP from a specific interface
```bash
linkinfo -i en0
```

### Capture continuously
```bash
linkinfo -i en0 -continuous
```

### Timeout if no discovery appears (default 30s)
```bash
linkinfo -i eth0 -timeout 10s
```

---

## 🧪 Example Output
```
======================================
Protocol     : LLDP
Interface    : en0
Discovered   : 2025-11-13T13:33:35-06:00
Source MAC   : aa:bb:cc:dd:ee:ff
System Name  : Switch-01
System Desc  : Cisco IOS 16.x
Chassis ID   : 00:11:22:33:44:55
Port ID      : Ethernet3/21
Port Desc    : RM5079 SYS ANALYST
VLAN         : 10
Voice VLAN   : 110
Tagged VLANs : 10,20,30
======================================
```

---

## 🧠 Technical Details

### LLDP
- Defined in **IEEE 802.1AB**
- TLVs decoded:
  - Chassis ID
  - Port ID
  - TTL
  - Port Description
  - System Name
  - System Description
  - Capabilities
  - Mgmt Address
  - Organizational TLVs:
    - **00:80:c2** (IEEE 802.1)
      - PVID
      - VLAN Name
      - Port VLAN ID
      - VLAN name mapping
      - Tagged VLAN list
    - **00:12:bb** (LLDP‑MED)
      - Voice VLAN

### CDP
- Cisco proprietary L2 protocol
- Frame structure: 802.3 + LLC/SNAP + CDP header + TLVs
- TLVs decoded:
  - Device ID
  - Port ID
  - Platform
  - Native VLAN

---

## 📄 License
This project is licensed under the **MIT License**.
See the `LICENSE` file for details.

---

## 🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss.

---

## ⭐ Star This Repo
If `linkinfo` helped you, please star the repository on GitHub!