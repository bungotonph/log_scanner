#!/bin/bash

LOGFILE="access_log_account"

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
  ./scan_account_acces_log.sh -sqlcheck -search="wp-config"

EOF
  exit 0
fi

echo "🔍 Scanning Apache-style access log: $LOGFILE"
echo "--------------------------------------------"

echo
echo "📄 Total Requests Logged: $(wc -l < "$LOGFILE")"

echo
echo "📟 HTTP Method Breakdown:"
grep -oE '"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)' "$LOGFILE" | tr -d '"' | sort | uniq -c | sort -nr

# Pattern detections — count only
php_shell_count=$(grep -Eic 'eval\(|assert\(|system\(|exec\(|passthru\(|shell_exec\(|popen\(|proc_open\(' "$LOGFILE")
base64_count=$(grep -Eic 'base64_decode|base64_encode' "$LOGFILE")
sql_count=$(grep -Ei "(union\s+select|select\s+.*from|insert\s+into|drop\s+table|or\s+1=1|(['\"])--)" "$LOGFILE" | wc -l)
cmd_count=$(grep -Eic 'cmd=|exec=|command=|execute=' "$LOGFILE")
xss_count=$(grep -Eic '(<|%3C)(script|img|svg)|onerror=|onload=' "$LOGFILE")
file_count=$(grep -Ei '\.php|\.cgi|\.exe|\.sh' "$LOGFILE" | grep -Ev 'wp-login\.php|wp-cron\.php|admin-ajax\.php|index\.php|xmlrpc\.php|wp-comments-post\.php' | wc -l)

echo
echo "🔸 PHP Shell Functions: $php_shell_count"
echo "🔸 Base64 Functions: $base64_count"
echo "🔸 SQL Injection: $sql_count"
echo "🔸 Command Execution Params: $cmd_count"
echo "🔸 XSS: $xss_count"
echo "🔸 Suspicious File Access: $file_count"

echo
echo "📊 Top 10 Requested URLs:"
awk '{print $7}' "$LOGFILE" | sort | uniq -c | sort -nr | head -n 10

echo
echo "🌐 Top 10 Source IPs:"
awk '{print $1}' "$LOGFILE" | sort | uniq -c | sort -nr | head -n 10

echo
echo "📤 Multipart/Form-Data POSTs:"
grep -i 'POST' "$LOGFILE" | grep -i 'multipart/form-data' | wc -l

echo
echo "🚨 Top Suspicious POST Targets:"
grep -i 'POST' "$LOGFILE" | grep -Ei '\.php' | grep -vE 'wp-login|wp-admin|admin-ajax|xmlrpc|wc-ajax' \
  | awk '{print $7}' | sort | uniq -c | sort -nr | head -n 10

echo
echo "📅 Possible File Upload Targets:"
grep -i 'POST' "$LOGFILE" | grep -i 'multipart/form-data' | awk '{print $7}' | sort | uniq -c | sort -nr | head -n 10

if [[ $php_shell_count -eq 0 && $sql_count -eq 0 && $xss_count -eq 0 ]]; then
  echo -e "\n✅ No critical web shell patterns detected."
else
  echo -e "\n🚨 Potential issues found. Use flags to view matching lines:"
fi

echo
echo "📘 Flags: -sqlcheck -xsscheck -phpshellcheck -base64check -cmdcheck -filecheck"

# Show matching lines *only* when flags are passed
$SHOW_SQL_LINES && echo -e "\n🧨 SQL Injection Matches:" && grep --color=always -Ei "(union\s+select|select\s+.*from|insert\s+into|drop\s+table|or\s+1=1|(['\"])--)" "$LOGFILE"
$SHOW_XSS_LINES && echo -e "\n🔦 XSS Matches:" && grep --color=always -Ei '(<|%3C)(script|img|svg)|onerror=|onload=' "$LOGFILE"
$SHOW_PHP_SHELL_LINES && echo -e "\n💀 PHP Shell Function Matches:" && grep --color=always -Ei 'eval\(|assert\(|system\(|exec\(|passthru\(|shell_exec\(|popen\(|proc_open\(' "$LOGFILE"
$SHOW_BASE64_LINES && echo -e "\n🔐 Base64 Matches:" && grep --color=always -Ei 'base64_decode|base64_encode' "$LOGFILE"
$SHOW_CMD_LINES && echo -e "\n🛠️ Command Parameter Matches:" && grep --color=always -Ei 'cmd=|exec=|command=|execute=' "$LOGFILE"
$SHOW_FILE_LINES && echo -e "\n📁 Suspicious File Access Matches:" && grep --color=always -Ei '\.php|\.cgi|\.exe|\.sh' "$LOGFILE" | grep -Ev 'wp-login\.php|wp-cron\.php|admin-ajax\.php|index\.php|xmlrpc\.php|wp-comments-post\.php'

if [[ -n "$SEARCH_STRING" ]]; then
  echo -e "\n🔍 Custom Search Matches for \"$SEARCH_STRING\":"
  grep --color=always -i "$SEARCH_STRING" "$LOGFILE"
fi

