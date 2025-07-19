

# **JSRecon v1.0 — JavaScript Reconnaissance & Analysis Toolkit**

**Author:** [Black1hp](https://github.com/black1hp)
**GitHub:** [github.com/black1hp/jsrecon](https://github.com/black1hp/jsrecon)

> Advanced JavaScript security analysis tool designed for **bug bounty hunters**, **penetration testers**, and **red team operators**.

---

## 🔍 Features

* **Comprehensive Pattern Detection**
  Detects across **13 categories** of sensitive data in JS files.

* **High-Performance Analysis**
  Built with Go’s optimized regex engine for fast scanning.

* **Multiple Output Formats**
  Supports output in **Text**, **JSON**, and to a **file**.

* **Advanced CLI Interface**
  Built with the **Cobra** framework for flexible usage.

* **Extensible Architecture**
  Easily add new detection patterns and modules.

---

## ⚙️ Installation

### Clone & Build

```bash
git clone https://github.com/black1hp/jsrecon
cd jsrecon
go build -o jsrecon cmd/jsrecon/main.go
```

### Or Install via `go install`

```bash
go install github.com/black1hp/jsrecon/cmd/jsrecon@latest
```

---

## 🚀 Usage

### 🔸 Basic Analysis

```bash
jsrecon analyze app.js
```

### 🔸 Advanced Options

| Option                 | Description                              |
| ---------------------- | ---------------------------------------- |
| `--verbose`            | Show detailed match information          |
| `--output results.txt` | Save results to a file                   |
| `--json`               | Output results in JSON format            |
| `--secrets-only`       | Display only sensitive findings          |
| `--debug`              | Enable debug logging for troubleshooting |

---

## 🧠 Detection Categories

1. **🌐 Endpoints & File Paths** – API endpoints, internal files
2. **🔗 Domains & URLs** – Cloud/CDN links, external domains
3. **🔑 Specific API Keys** – Hardcoded service keys
4. **⚠️ Generic Tokens** – Auth/session tokens needing manual review
5. **👤 Credentials** – Usernames, passwords, DB URIs
6. **💳 Payment Data** – CC numbers, SSNs, and billing info
7. **🔐 Private Keys** – RSA/ECDSA private keys
8. **🔓 Public Keys** – SSH or JWT public keys
9. **🍪 Cookies** – Session/auth cookies
10. **💾 Storage** – Local/session storage artifacts
11. **🌍 IP Addresses** – Internal/external IP addresses
12. **📦 Base64 Strings** – Encoded secrets
13. **💬 Comments** – Hidden clues or leftover comments

---

## 📤 Output Formats

* **Text** — Human-readable with color highlights
* **JSON** — For automation pipelines and integrations
* **File** — Save analysis results for later inspection

---

## 🛠 Setup from Scratch

```bash
mkdir jsrecon && cd jsrecon
go mod init github.com/black1hp/jsrecon
```

### Install Dependencies

```bash
go get github.com/spf13/cobra@latest
go get github.com/spf13/viper@latest
```

### Build the Tool

```bash
go build -o jsrecon cmd/jsrecon/main.go
```

### Example Run

```bash
./jsrecon analyze target.js --verbose --output results.txt
```

---

## 📈 Key Improvements Over Python Version

* ⚡ **3–5× Faster** with Go’s high-performance regex engine
* 🧠 **Better Memory Efficiency** for large JS files
* 💻 **Modern CLI** built with Cobra framework
* 🤖 **JSON Output** for CI pipelines and integration
* 🔍 **Enhanced Pattern Coverage** — all regexes validated and improved
* 🧱 **Cleaner Architecture** for easy extension and maintenance

---

## 🤝 Contributing

Pull requests and issues are welcome!
If you have a new detection idea, submit a PR or open a feature request.

---

## 📄 License

This project is licensed under the **MIT License**.
See the [LICENSE](https://github.com/black1hp/jsrecon/blob/main/LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is intended **only for authorized security testing and research**.
Use responsibly and ensure compliance with all applicable laws.
