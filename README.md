# Log Scanner

This repository provides lightweight Bash-based log scanning tools for identifying potentially malicious access patterns in web server logs. These tools are ideal for cPanel environments or other Apache-style access logs.

## 📂 Scripts Included

### `scan_cpanel_access_log.sh`
Scans the `access_log` file found in cPanel environments. It detects potential security threats such as:
- SQL injection attempts
- XSS payloads
- PHP shell usage
- Obfuscated base64 patterns
- Suspicious file access
- Suspicious POST uploads

### `scan_account_access_log.sh`
Targets Apache-style logs (e.g. `access_log_account`) with similar detection mechanisms, ideal for non-cPanel setups.

## 🔍 Usage
```bash
./scan_cpanel_access_log.sh [options]
./scan_account_access_log.sh [options]
```

### Available Flags
- `-sqlcheck`        Show lines matching SQL injection patterns
- `-xsscheck`        Show lines with potential XSS payloads
- `-phpshellcheck`   Detect PHP shell function usage (eval, exec, etc.)
- `-base64check`     Highlight base64 patterns (obfuscation)
- `-cmdcheck`        Show command injection parameters (cmd=, exec=, etc.)
- `-filecheck`       Detect suspicious file access (.php, .exe, .sh, etc.)
- `-search=STRING`   Search for a custom string in the log
- `--help`           Display usage instructions

### Example:
```bash
./scan_account_access_log.sh -sqlcheck -search="wp-config"
```

## 📘 Detection Glossary
| Detection Type       | Why It’s Suspicious                                                                 |
|----------------------|------------------------------------------------------------------------------------|
| SQL Injection        | Exploits DB queries via malicious input like `UNION SELECT`, `OR 1=1`, etc.       |
| XSS (Cross-site)     | Injects scripts into user pages to steal cookies, hijack sessions, etc.           |
| PHP Shell Functions  | Functions like `eval()` or `system()` enable remote code execution if misused     |
| base64 Encode/Decode | Often used to hide payloads or obfuscate commands                                 |
| Command Params       | Query parameters like `cmd=ls` or `exec=` could indicate command injection        |
| Suspicious Files     | Accessing `.php`, `.exe`, or `.sh` files might point to backdoor or upload scans |

## ✅ Recommendations
- Review flagged lines manually
- Investigate top IPs making suspicious requests
- Harden inputs and sanitize user data in web apps
- Monitor for repeated attacks from the same sources

## 📜 License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

Pull requests and suggestions are welcome!

