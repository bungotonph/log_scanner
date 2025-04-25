#!/bin/bash

LOGFILE="access_log"

# Flags
SHOW_SQL_LINES=false
SHOW_XSS_LINES=false
SHOW_PHP_SHELL_LINES=false
SHOW_BASE64_LINES=false
SHOW_CMD_LINES=false
SHOW_FILE_LINES=false
SEARCH_STRING=""

# Check for flags
for arg in "$@"; do
  case $arg in
    -sqlcheck) SHOW_SQL_LINES=true ;;
    -xsscheck) SHOW_XSS_LINES=true ;;
    -phpshellcheck) SHOW_PHP_SHELL_LINES=true ;;
    -base64check) SHOW_BASE64_LINES=true ;;
    -cmdcheck) SHOW_CMD_LINES=true ;;
    -filecheck) SHOW_FILE_LINES=true ;;
    -search=*) SEARCH_STRING="${arg#*=}" ;;
  esac
done

if [[ "$1" == "--help" ]]; then
  cat << EOF
Usage: ./scan_account_acces_log.sh [options]

Options:
  -sqlcheck        Show lines matching SQL injection patterns
  -xsscheck        Show lines with potential XSS payloads
  -phpshellcheck   Detects PHP shell function usage (eval, system, etc.)
  -base64check     Flags use of base64_encode/decode (often used for obfuscation)
  -cmdcheck        Matches suspicious command parameters (cmd=, exec=, etc.)
  -filecheck       Shows access to suspicious files (.php, .exe, .sh, etc.)
  -search=STRING   Custom keyword to search for in logs
  --help           Show this help message

Example:
  ./scan_cpanel_acces_log.sh -sqlcheck -search="wp-config"

EOF
  exit 0
fi

echo "🔍 Scanning access log: $LOGFILE"
echo "----------------------------------"

# Total lines
echo
echo "📄 Total Requests Logged: $(wc -l < "$LOGFILE")"

# HTTP Method Breakdown
echo
echo "📟 HTTP Method Breakdown:"
grep -oE '"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)' "$LOGFILE" | tr -d '"' | sort | uniq -c | sort -nr

# Pattern match counts
echo
php_shell=$(grep -Eic 'eval\(|assert\(|system\(|exec\(|passthru\(|shell_exec\(|popen\(|proc_open\(' "$LOGFILE")
base64=$(grep -Eic 'base64_decode|base64_encode' "$LOGFILE")
sql_inj=$(grep -Ei "(union\s+select|select\s+.*from|insert\s+into|drop\s+table|or\s+1=1|(['\"])--)" "$LOGFILE")
cmd_exec=$(grep -Eic 'cmd=|exec=|command=|execute=' "$LOGFILE")
xss_hits=$(grep -Eic '(<|%3C)(script|img|svg)|onerror=|onload=' "$LOGFILE")
suspicious_files=$(grep -Eic '\\.php|\\.cgi|\\.exe|\\.sh' "$LOGFILE")

echo "🔸 PHP Shell Functions: $php_shell"
echo "🔸 Base64 Functions: $base64"
echo "🔸 SQL Injection: $sql_inj"
echo "🔸 Command Execution Params: $cmd_exec"
echo "🔸 XSS: $xss_hits"
echo "🔸 Suspicious File Access: $suspicious_files"

# Top 10 Requested URLs
echo
echo "📊 Top 10 Requested URLs:"
awk '{print $7}' "$LOGFILE" | sort | uniq -c | sort -nr | head -n 10

# Top source IPs
echo
echo "🌐 Top 10 Source IPs:"
grep -oE 'X-Forwarded-For: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LOGFILE" | awk '{print $2}' | sort | uniq -c | sort -nr | head -n 10

# Suspicious Activity Checks
echo
echo "🔎 Additional Suspicious Activity Checks"
echo "---------------------------------------"

# POST with multipart/form-data (file uploads)
echo -n "📤 Multipart/Form-Data POSTs: "
grep -i 'POST' "$LOGFILE" | grep -i 'multipart/form-data' | wc -l

# Suspicious POST targets
echo
echo "🚨 Top Suspicious POST Targets:"
grep -i 'POST' "$LOGFILE" | grep -Ei '\.php' | grep -vE 'wp-login|wp-admin|admin-ajax|xmlrpc|wc-ajax' \
  | awk '{print $7}' | sort | uniq -c | sort -nr | head -n 10

# Possible file upload destinations
echo
echo "📅 Possible File Upload Targets:"
grep -i 'POST' "$LOGFILE" | grep -i 'multipart/form-data' | awk '{print $7}' | sort | uniq -c | sort -nr | head -n 10

# Final summary
if [[ $php_shell -eq 0 && $sql_inj -eq 0 && $xss_hits -eq 0 ]]; then
  echo -e "\n📅 Scan complete. ✅ No high-confidence web shell activity detected."
else
  echo -e "\n🚨 Scan complete. Potential issues detected. Please review above entries."
fi

# List available parameter to check specific logs
echo
echo "📘 Available Parameters to View Matching Log Lines:"
echo "   Use these options with the script to print matched entries:"
echo "   -----------------------------------------------------------"
echo "   -sqlcheck         Show potential SQL injection lines"
echo "   -xsscheck         Show potential XSS attack lines"
echo "   -phpshellcheck    Show suspicious PHP shell function usage"
echo "   -base64check      Show lines with base64_encode/decode"
echo "   -cmdcheck         Show command execution parameter usage"
echo "   -filecheck        Show suspicious file extension access"
echo
echo "💡 Example usage:"
echo "   ./scan_access_log.sh -sqlcheck -xsscheck"

# Detailed view if flags are used
echo

if $SHOW_SQL_LINES; then
  echo "🧨 SQL Injection Matching Lines:"
  grep --color=always -Ei "(union\s+select|select\s+.*from|insert\s+into|drop\s+table|or\s+1=1|(['\"])--)" "$LOGFILE"
  echo
fi

if $SHOW_XSS_LINES; then
  echo "🔦 XSS Matching Lines:"
  grep --color=always -Ei '(<|%3C)(script|img|svg)|onerror=|onload=' "$LOGFILE"
  echo
fi

if $SHOW_PHP_SHELL_LINES; then
  echo "💀 PHP Shell Function Lines:"
  grep --color=always -Ei 'eval\(|assert\(|system\(|exec\(|passthru\(|shell_exec\(|popen\(|proc_open\(' "$LOGFILE"
  echo
fi

if $SHOW_BASE64_LINES; then
  echo "🔐 Base64 Encoding/Decoding Lines:"
  grep --color=always -Ei 'base64_decode|base64_encode' "$LOGFILE"
  echo
fi

if $SHOW_CMD_LINES; then
  echo "🛠️ Command Execution Param Lines:"
  grep --color=always -Ei 'cmd=|exec=|command=|execute=' "$LOGFILE"
  echo
fi

if $SHOW_FILE_LINES; then
  echo "📁 Suspicious File Access Lines:"
  grep --color=always -Ei '\.php|\.cgi|\.exe|\.sh' "$LOGFILE"
  echo
fi

if [[ -n "$SEARCH_STRING" ]]; then
  echo -e "\n🔍 Custom Search Matches for \"$SEARCH_STRING\":"
  grep --color=always -i "$SEARCH_STRING" "$LOGFILE"
fi
