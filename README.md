<div align="center">

# 🛡️ DriverSentinel 🛡️

### **Vulnerable Windows Driver Scanner**

[![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Go Version](https://img.shields.io/badge/Go-1.24-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![LOLDrivers](https://img.shields.io/badge/Powered_by-LOLDrivers.io-orange?style=for-the-badge)](https://loldrivers.io)

**DriverSentinel** is a security tool developed in Go that detects malicious and vulnerable drivers on Windows systems by comparing them against the [LOLDrivers.io](https://loldrivers.io) database.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [How It Works](#-how-it-works)

---

</div>

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [How It Works](#-how-it-works)
- [Detection Examples](#-detection-examples)
- [Building from Source](#-building-from-source)
- [Detection Logic](#-detection-logic)
- [License](#-license)
- [Credits](#-credits)

---

## ✨ Features

- 🔍 **Smart Scanning**: Detects vulnerable drivers using SHA256 hash and filename matching
- 🌐 **Automatic Updates**: Automatic synchronization with LOLDrivers.io database
- ⚡ **High Performance**: Optimized scanning with in-memory indices for fast lookups
- 📊 **Real-Time Progress**: Live visualization of scanned files
- 🎯 **Category-Based Detection**: Different criteria based on threat type (malicious vs. vulnerable)
- 🗂️ **Multiple Scan Modes**: 
  - Specific path scanning (recursive or non-recursive)
  - Automatic scanning of common Windows locations
- 📝 **Detailed Reports**: Complete information about detected drivers, including exploitation commands
- 🔒 **Only .sys Files**: Specific filtering for Windows kernel drivers

---

## 💻 Requirements

- **Operating System**: Windows 10/11 (x64)
- **Privileges**: Administrator (required to scan system locations)
- **Space**: ~10 MB for executable and database

---

## 📥 Installation

### Direct Download (Recommended)

1. Download the latest version from [Releases](https://github.com/bI8d0/DriverSentinel/releases)
2. Extract the `.zip` file
3. Run `driversentinel.exe` from a terminal with administrator privileges

### From Source

```bash
git clone https://github.com/bI8d0/DriverSentinel.git
cd DriverSentinel
go run .\build.go
```

---

## 🚀 Usage

### Basic Syntax

```cmd
driversentinel.exe [options]
```

### Options

| Option | Description |
|--------|-------------|
| `-common` | Scan common Windows driver locations (requires Admin) |
| `-path <path>` | Scan a specific directory |
| `-r` | Recursive mode (scan subdirectories) |

### Examples

#### 1. Scan common system locations (Recommended)

```cmd
driversentinel.exe -common
```

Automatically scans:
- `C:\Windows\System32\drivers`
- `C:\Windows\SysWOW64\drivers`
- `C:\Windows\System32\DriverStore\FileRepository`
- And other critical locations

#### 2. Scan a specific directory

```cmd
driversentinel.exe -path C:\MyFolder
```

#### 3. Scan recursively

```cmd
driversentinel.exe -path C:\MyFolder -r
```

#### 4. Scan an entire drive (⚠️ may take a while)

```cmd
driversentinel.exe -path C:\ -r
```

---

## 🔬 How It Works

### 1️⃣ Database Synchronization

On startup, DriverSentinel:
- Checks the LOLDrivers.io database using **ETag** or **SHA256**
- Automatically downloads updates if available
- Uses a local copy if there's no internet connection

### 2️⃣ In-Memory Indexing

Builds optimized indices for fast searching:
- **Hash Index**: SHA256 of known samples
- **Filename Index**: OriginalFilename of known samples

### 3️⃣ File Scanning

For each `.sys` file found:
1. Compares the filename (fast lookup)
2. If there's a match, calculates the SHA256
3. Applies detection logic based on category
4. Reports matches found

### 4️⃣ Results Report

Shows detailed information:
- File path
- SHA256 hash
- Match type (filename, hash, or both)
- Vulnerable driver details
- Known exploitation commands (if applicable)

---

## 📊 Detection Examples

### Program Output

```
=== DriverSentinel - Vulnerable Driver Scanner by bI8d0 ===

[repository] Local copy is up to date
[repository] Loaded 1337 drivers
Total drivers loaded: 1337

[scanner] Indices built: 5432 hashes, 5432 filenames
[scanner] Valid extension: .sys
[scanner] Starting scan of: C:\Windows\System32\drivers

[scanner] Scanning (523 files): C:\Windows\System32\drivers\some_driver.sys
⚠ DETECTED: C:\Windows\System32\drivers\vulnerable.sys (Type: both, Category: malicious)

[scanner] Scan completed in 2.34s
[scanner] Files scanned: 523
[scanner] Vulnerabilities found: 1

⚠ ALERT: Found 1 vulnerable driver(s)
================================================================================

[1] VULNERABLE FILE DETECTED
--------------------------------------------------------------------------------
  Path:          C:\Windows\System32\drivers\vulnerable.sys
  SHA256:        abc123def456...
  Match Type:    both
  Driver ID:     vulnerable-driver-id
  Category:      malicious

  Vulnerable Driver Details:
    Original:    vulnerable.sys
    Company:     Malicious Corp
    Product:     Malicious Product
    Version:     1.0.0
    Description: Known vulnerable driver
    HVCI:        False

  Exploitation Commands:
    ─── Command 1 ───
    Use Case:     Privilege Escalation
    Privileges:   Administrator
    OS:           Windows 10/11
    Description:  Known exploit method
    Command:      sc.exe create vuln binPath= ...
    Resources:    https://example.com/advisory
================================================================================
```

---

## 🔨 Building from Source

### Prerequisites

- [Go 1.24+](https://golang.org/dl/)
- Windows 10/11
- Git

### Steps

```bash
# Clone the repository
git clone https://github.com/bI8d0/DriverSentinel.git
cd DriverSentinel

# Install dependencies
go mod download

# Build
go run .\build.go

# Run
.\build\driversentinel.exe -common
```

### Optimized Build

```bash
go build -ldflags="-s -w" -o build/driversentinel.exe
```

---

## 🧠 Detection Logic

DriverSentinel applies **different criteria** based on driver category:

### 🔴 Malicious Drivers (`category: "malicious"`)

- **Reports if**: Filename **OR** Hash match (any match is critical)
- **Reason**: Malicious drivers must be detected regardless of renaming

### 🟡 Vulnerable Drivers (`category: "vulnerable driver"`)

- **Reports if**: Filename **AND** Hash match (both must match)
- **Reason**: Avoids false positives from generic names of legitimate drivers

### 🟢 Other Categories

- **Reports for**: Safety (precaution for new categories)

### Match Types

| Match Type | Description |
|-----------|-------------|
| `filename` | Only the filename matches |
| `sha256` | Only the hash matches (renamed file) |
| `both` | Both filename and hash match (perfect match) |

---

### Areas for Improvement

- [ ] Parallel scanning support (goroutines)
- [ ] Report export (JSON, CSV, HTML)
- [ ] Graphical user interface (GUI)
- [ ] Silent mode for automation
- [ ] SIEM integration
- [ ] Automatic quarantine of detected drivers

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

- **Author**: [bI8d0](https://github.com/bI8d0/)
- **Database**: [LOLDrivers.io](https://loldrivers.io) - An amazing community project that maintains the vulnerable drivers database
- **Community**: Special thanks to all security researchers who contribute to LOLDrivers

### Technologies Used

- [Go](https://golang.org/) - Programming language
- [uilive](https://github.com/gosuri/uilive) - Real-time progress bar
- [LOLDrivers API](https://loldrivers.io/api/) - Vulnerable drivers database

---

<div align="center">

### ⚠️ Disclaimer

This tool is for educational and defensive security purposes only.  
**DO NOT** use it for malicious or illegal activities.  
The author is not responsible for misuse of this tool.

---

**Made with ❤️ and Go** 

If you find it useful, consider giving it a ⭐!

</div>
