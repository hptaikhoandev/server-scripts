#!/usr/bin/env bash
# =============================================================================
#  wp-incident-fix.sh  —  Kiểm tra & dọn đợt mã độc WordPress (10/2026)
#  Dành cho server WPTT / OpenLiteSpeed (site nằm ở /usr/local/lsws/<domain>/html)
#
#  Xử lý các thành phần đã gặp:
#   - Backdoor "index-importer-pad" (giả plugin "Jolt Runner", dấu /* SCV:x.y.z */)
#     + bản sao trong mu-plugins + bản sao ẩn .q_ .sd_ .rd_ .wr_ .gk_
#   - Mã tự cài lại trong theme functions.php (SC_TH_BEGIN)
#   - Mã đánh cắp mật khẩu đăng nhập (_wp_load_compat_layer / "maintenance service")
#   - Webshell 10676 byte tên ngẫu nhiên, wp-cron-xxxx.php, thư mục "well-known" giả
#   - php.ini / .user.ini tắt bảo mật, index.php bị xoá trắng, core WP bị sửa,
#     .htaccess bị sửa, file PHP trong uploads
#   - Tiến trình bash chạy nền dưới user website, crontab của user website
#
#  CÁCH DÙNG (chạy bằng root):
#    bash wp-incident-fix.sh check              # CHỈ kiểm tra, không sửa gì
#    bash wp-incident-fix.sh fix                # dọn toàn bộ site
#    bash wp-incident-fix.sh fix domain.com     # dọn 1 site
#    bash wp-incident-fix.sh restore /root/wp-incident-<tg> [loại] [domain]   # trả lại file đã cách ly
#    bash wp-incident-fix.sh admins [domain]         # LIỆT KÊ admin độc (tạo từ INFECT_DATE hoặc ngày giả <2000)
#    bash wp-incident-fix.sh admins-apply [domain]   # XOÁ admin độc, chuyển bài cho admin gốc, đăng xuất mọi phiên, đổi salt
#    GOOGLE_KEEP="abc123... def456..." bash wp-incident-fix.sh fix   # giữ file google<mã>.html của bạn
#    bash wp-incident-fix.sh all [domain]       # CHẠY TRỌN: php2shell -> fix(+harden) -> admins -> admins-apply
#    bash wp-incident-fix.sh php2shell          # cập nhật lsphp vá PHP2Shell (CVE-2026-109618/109619), báo lỗi nếu cập nhật hỏng
#    bash wp-incident-fix.sh harden             # lsphp: disable_functions + session.upload_progress Off, chặn C2
#
#  - File độc KHÔNG bị xoá, mà được chuyển vào /usr/local/lsws/_quarantine_<thời gian>/
#    (giữ nguyên đường dẫn, chỉ root đọc được). Muốn khôi phục thì mv ngược lại.
#  - Báo cáo: /root/wp-incident-<thời gian>/  (summary.txt, global.log, sites/<domain>.log)
#  - Script KHÔNG chạy code WordPress bằng root.
# =============================================================================

set -o pipefail
shopt -s nullglob

MODE=${1:-check}
ONLY=${2:-}
LSWS=${LSWS:-/usr/local/lsws}
KEEP_ADMINS=${KEEP_ADMINS-adminhp}            # admin của bạn: luôn GIỮ (bất kể ngày tạo), admins-apply đổi mật khẩu mới
GOOGLE_KEEP=${GOOGLE_KEEP:-}                   # mã file google<mã>.html CỦA BẠN tạo sau mốc nhiễm, cách nhau dấu cách
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"   # tránh 8G/Cloudflare chặn curl
INFECT_DATE=${INFECT_DATE:-2026-10-15}          # mốc bắt đầu bị nhiễm (để soát admin mới, .htaccess.bk)
TS=$(date +%Y%m%d-%H%M%S)
OUT=${OUT:-/root/wp-incident-$TS}
Q="$LSWS/_quarantine_$TS"

SHELL_MD5=(b591035462fde056936e45098094168a)     # webshell 10676 byte
C2_HOSTS=(ethereum-sepolia-rpc.publicnode.com)    # nơi mã đánh cắp mật khẩu lấy địa chỉ C2

CORE_ROOT=" index.php wp-activate.php wp-blog-header.php wp-comments-post.php wp-config.php wp-config-sample.php wp-cron.php wp-links-opml.php wp-load.php wp-login.php wp-mail.php wp-settings.php wp-signup.php wp-trackback.php xmlrpc.php "

# Dấu hiệu chắc chắn là backdoor -> cách ly nguyên file/plugin
SIG_BACKDOOR='/\* SCV:[0-9]|/\* SCOCV:[0-9]|_sc_mkdir|_sc_fpc|get_option\(.optimizer.\)|Author: WordPress Core Team|0d4f69bb38f2354a6d896d6a222a4bf5|Plugin Name: maintenance service|ethereum-sepolia-rpc|wpanel|class-wp-locale-data|gzuncompr.\.?.?ess|Plugin Name: WP Compatibility Patch|sc_cron_recovery|sc_cron_fetch|get_option\( *.sso_token|mu_protector|\[.compat.\] *!== *.verify|BYTE_BUNK|@touch\(\$value, *\$randomTimestamp|@eval\(\$[A-Za-z_]+(->[A-Za-z_]+)?\);|unset\( *\$plugins\[ *plugin_basename\( *__FILE__ *\) *\] *\)|var _0x[0-9a-f]{12}=\[[0-9]{1,3},|_GET\[.delete_self.\]|ini_set\(.disable_functions., *..\)'
# Mã bị cấy vào file thật -> cắt đoạn mã, giữ file
SIG_INJECT='SC_TH_BEGIN|_wp_load_compat_layer|// WPANEL:BEGIN|new Function\(_code\)|eth_call'
# Dấu hiệu webshell chung (dùng cho file lạ ở gốc web / wp-config)
SIG_WEAK='eval[[:space:]]*\(|base64_decode|gzinflate|gzuncompress|str_rot13|\$_COOKIE\[|assert[[:space:]]*\(|create_function'
# Mã làm rối kiểu webshell (gần như không có trong code thật) -> cách ly từng file ở bất kỳ đâu
SIG_OBF='gzuncompr["'"'"'][[:space:]]*\.[[:space:]]*["'"'"']ess|["'"'"']e["'"'"'][[:space:]]*\.[[:space:]]*["'"'"']xit["'"'"']|["'"'"']exi["'"'"'][[:space:]]*\.[[:space:]]*["'"'"']t["'"'"']|move_uploaded_file\(\$saw|\$_(POST|GET|REQUEST|COOKIE)\[[^]]{1,40}\][[:space:]]*\(|'base'\.'64'|'gzinflat'\.'e'|'st'\.'r'\.'_rot'|eval\(\$[A-Za-z_]+\(\$[A-Za-z_]+\(\$[A-Za-z_]+\('
# Dấu hiệu yếu hơn (có thể gặp trong code thật) -> chỉ cách ly nếu file mới tạo/sửa sau ngày nhiễm
SIG_OBF_WEAK='eval[[:space:]]*\([[:space:]]*\$[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\('
# .htaccess mở quyền chạy PHP (hacker đặt cạnh webshell)
HT_OPEN='Require all granted|Allow From All'
# .htaccess bị hacker sửa (chặn mọi PHP trừ webshell, chạy PHP trong file ảnh...)
HT_BAD='FilesMatch[^>]*(py\|exe\|php|\^\(index)|auto_prepend|AddHandler|SetHandler'

WP=$(command -v wp || true)
PHPBIN=$(command -v php || ls -1 "$LSWS"/lsphp*/bin/php 2>/dev/null | sort -V | tail -1)
export PHPBIN
CUTOFF=$(date -d "$INFECT_DATE" +%s)
declare -A CNT SEEN
LOG=/dev/null

case "$MODE" in check|fix|harden|restore|admins|admins-apply|php2shell|all) ;; *) sed -n '/CÁCH DÙNG/,/^#  - File/p' "$0"; exit 1;; esac
[ "$(id -u)" = 0 ] || { echo "Cần chạy bằng root"; exit 1; }
mkdir -p "$OUT/sites"
LOG="$OUT/global.log"
exec </dev/null   # không lệnh nào được đợi nhập từ bàn phím

say()  { echo "$*" | tee -a "$LOG"; }
isfix(){ [ "$MODE" = fix ]; }

# ---------------------------------------------------------------- tiện ích
# qmove <loại> <đường dẫn tuyệt đối>: cách ly (fix) hoặc chỉ báo (check)
qmove() {
  local cat=$1 p=$2 rel
  [ -e "$p" ] || [ -L "$p" ] || return 0
  rel=${p#"$LSWS"/}
  # bỏ qua nếu chính nó hoặc thư mục cha đã được xử lý
  local a=$p
  while [ "${#a}" -gt "${#LSWS}" ]; do [ -n "${SEEN[$a]:-}" ] && return 0; a=$(dirname "$a"); done
  SEEN[$p]=1
  CNT[$cat]=$(( ${CNT[$cat]:-0} + 1 ))
  if isfix; then
    local dst="$Q/$rel" k=1
    while [ -e "$dst" ]; do k=$((k+1)); dst="$Q/$rel.$k"; done
    mkdir -p "$(dirname "$dst")"
    chattr -i "$p" 2>/dev/null
    mv -n -T "$p" "$dst" 2>/dev/null
    if [ -e "$p" ]; then say "  [LỖI MOVE]  ($cat) $rel"; else say "  [CÁCH LY]   ($cat) $rel  ==> ${dst#"$LSWS"/}"; fi
  else
    say "  [PHÁT HIỆN] ($cat) $rel"
  fi
}

step() { printf '     \033[2m… %s (%s)\033[0m\n' "$*" "$(date +%T)" >&2; }   # tiến độ, chỉ hiện ra màn hình

review() { CNT[can-xem]=$(( ${CNT[can-xem]:-0} + 1 )); say "  [CẦN XEM]   $*"; }

is_shell_md5() {
  local m h; m=$(md5sum < "$1" 2>/dev/null | cut -c1-32)
  for h in "${SHELL_MD5[@]}"; do [ "$m" = "$h" ] && return 0; done
  return 1
}

http_check() {
  local r
  r=$(curl -sk -m 15 -A "$UA" -o /dev/null -w '%{http_code} %{size_download}' \
       --resolve "$1:443:127.0.0.1" "https://$1/" 2>/dev/null)
  [[ $r =~ ^[0-9]{3}\ [0-9]+$ ]] || r="000 0"
  # LiteSpeed có thể không map domain trên 127.0.0.1 (trả 404 mặc định) -> thử qua địa chỉ công khai
  if [[ ! $r =~ ^[23] ]]; then
    local r2
    r2=$(curl -sk -m 15 -A "$UA" -o /dev/null -w '%{http_code} %{size_download}' "https://$1/" 2>/dev/null)
    [[ $r2 =~ ^[0-9]{3}\ [0-9]+$ ]] && [[ ! $r2 =~ ^000 ]] && r=$r2
  fi
  echo "$r"
}

write_cleaner() {
cat > "$OUT/clean_inject.py" <<'PYEOF'
import re, sys, subprocess, os
mode = sys.argv[1]
for p in sys.argv[2:]:
    try:
        s = open(p, encoding="utf-8", errors="surrogateescape").read()
    except Exception as e:
        print("   LỖI ĐỌC", p, e); continue
    o = s
    # 1) Khối SC_TH (tự cài lại backdoor) — có thể có nhiều khối
    for _ in range(20):
        i = s.find("/* SC_TH_BEGIN")
        if i == -1: break
        st = s.rfind("<?php", 0, i); st = st if st != -1 and i - st < 20 else i
        e = s.find("SC_TH_END", i)
        if e == -1: en = len(s)
        else:
            nl = s.find("\n", e); en = len(s) if nl == -1 else nl + 1
        s = s[:st] + s[en:]
    # 1b) Khối "wpanel agent" giữa // WPANEL:BEGIN ... // WPANEL:END(-AGENT)
    for _ in range(20):
        i = s.find("// WPANEL:BEGIN")
        if i == -1: break
        m = re.compile(r"// WPANEL:END[^\n]*").search(s, i)
        if not m: break
        nl = s.find("\n", m.end()); s = s[:i] + s[(len(s) if nl == -1 else nl + 1):]
    # 1c) Script JS độc chèn ngoài PHP giữa <!-- xxx --> ... <!-- /xxx --> (EtherHiding: đọc C2 từ blockchain -> Cloudflare giả/ClickFix)
    def _js_block(m):
        inner = m.group(0)
        return "" if ("fromCharCode" in inner and ("new Function" in inner or "eth_call" in inner)) else inner
    s = re.sub(r"<!-- ([A-Za-z0-9_-]{3,24}) -->\s*(?:<\?php\s*\?>\s*)?<script>.*?</script>\s*<!-- /\1 -->[ \t]*\n?", _js_block, s, flags=re.S)
    # 2) Khối _wp_load_compat_layer (thả mã đánh cắp mật khẩu)
    s = re.sub(r"[^\n]*add_action\(\s*['\"]init['\"]\s*,\s*['\"]_wp_load_compat_layer['\"]\s*\);[^\n]*\n?", "", s)
    for _ in range(20):
        k = s.find("function _wp_load_compat_layer")
        if k == -1: break
        b = s.find("{", k)
        if b == -1: break
        d = 0; j = b
        while j < len(s):
            if s[j] == "{": d += 1
            elif s[j] == "}":
                d -= 1
                if d == 0: break
            j += 1
        s = s[:k] + s[j+1:]
    if o.lstrip().startswith("<?php") and "<?php" not in s:
        head = "<?php\n// Add custom Theme Functions here\n" if os.path.basename(p) == "functions.php" else "<?php\n"
        s = head + (s.strip() + "\n" if s.strip() else "")
    if s == o:
        print("   SẠCH ", p); continue
    tag = "[ĐÃ LÀM SẠCH]" if mode == "--apply" else "[PHÁT HIỆN] (ma-cay-vao-file)"
    print(f"  {tag} {p}: {o.count(chr(10))} -> {s.count(chr(10))} dòng")
    if mode != "--apply": continue
    with open(p, "w", encoding="utf-8", errors="surrogateescape") as f: f.write(s)
    php = os.environ.get("PHPBIN") or "php"
    try:
        r = subprocess.run([php, "-l", p], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        bad = r.returncode != 0
    except FileNotFoundError:
        bad = True   # không kiểm tra được cú pháp -> không dám ghi
    if bad:
        with open(p, "w", encoding="utf-8", errors="surrogateescape") as f: f.write(o)
        print("  [CẦN XEM]   LỖI CÚ PHÁP sau khi cắt (hoặc không có php để kiểm tra) -> đã khôi phục file gốc, cần sửa tay:", p)
PYEOF
}

# ---------------------------------------------------------------- tiến trình lạ
# Mọi tiến trình của user website, TRỪ worker LSAPI thuần ("lsphp"), đều bị coi là lạ:
# bash/sh loop, php CLI chạy file trong wp-content/.sc_* (--sc-cli), miner...
kill_site_procs() {
  local u pid user comm args
  declare -A SU=()
  for u in $(stat -c %U "$LSWS"/*/html 2>/dev/null | sort -u); do
    [ "$u" = root ] || [ "$u" = nobody ] || SU[$u]=1
  done
  while read -r pid user comm args; do
    [ -n "${SU[$user]:-}" ] || continue
    [ "$args" = lsphp ] && continue
    if [[ $args == lsphp:/* ]]; then say "  [TIẾN TRÌNH] request PHP đang chạy dở (sẽ khởi động lại cùng lsphp): pid=$pid ${args:6:160}"
    else say "  [TIẾN TRÌNH] pid=$pid user=$user ${args:0:170}"; fi
    isfix && kill -9 "$pid" 2>/dev/null && say "    -> đã kill"
  done < <(ps -eo pid=,user:64=,comm=,args= 2>/dev/null)
}

# ---------------------------------------------------------------- bước toàn server
global_pre() {
  LOG="$OUT/global.log"
  say "############ KIỂM TRA TOÀN SERVER ($(hostname)) — chế độ: $MODE"
  declare -A SU=()
  local u pid user comm args
  for u in $(stat -c %U "$LSWS"/*/html 2>/dev/null | sort -u); do
    [ "$u" = root ] || [ "$u" = nobody ] || SU[$u]=1
  done
  say "== Số user website: ${#SU[@]}"

  say "== Tiến trình lạ chạy dưới user website (user web chỉ nên có tiến trình 'lsphp' của web)"
  kill_site_procs
  sleep 1; kill_site_procs   # lần 2: bắt các tiến trình vừa được sinh lại
  if command -v crontab >/dev/null; then
    say "== Crontab của user website"
    for u in "${!SU[@]}"; do
      local c; c=$(crontab -l -u "$u" 2>/dev/null | grep -v '^\s*#' | grep .)
      [ -z "$c" ] && continue
      say "  [CRONTAB] $u:"; echo "$c" | sed 's/^/      /' | tee -a "$LOG"
      if isfix; then echo "$c" > "$OUT/crontab-$u.txt"; crontab -r -u "$u"; say "    -> đã xoá (lưu ở $OUT/crontab-$u.txt)"; fi
    done
  fi

  say "== File của user website trong /tmp /var/tmp /dev/shm"
  # sc_<hex>.lock / sc_XXXXXX = khoá & file tạm của backdoor họ "sc_"; phpXXXXXX cũ = file upload PHP bỏ dở (có thể do khai thác)
  local tq="$LSWS/_quarantine_$TS/_tmp" tf n=0
  for u in "${!SU[@]}"; do
    while IFS= read -r tf; do
      b=${tf##*/}
      if [[ $b =~ ^sc_ ]] || { [[ $b =~ ^php[A-Za-z0-9]{6}$ ]] && [ -n "$(find "$tf" -maxdepth 0 -mmin +60 2>/dev/null)" ]; }; then
        if isfix; then mkdir -p "$tq"; mv -f "$tf" "$tq/" 2>/dev/null && n=$((n+1)); else say "  [TMP] $tf  ($(stat -c '%y' "$tf" | cut -c1-16), user $u)"; fi
      else say "  [TMP] $tf  ($(stat -c '%y' "$tf" | cut -c1-16), user $u)"; fi
    done < <(find /tmp /var/tmp /dev/shm -maxdepth 1 -user "$u" ! -name 'wordpress-*-no-content-*' 2>/dev/null)
  done
  [ $n -gt 0 ] && say "  -> đã cách ly $n file tạm của mã độc (sc_*, php* bỏ dở) vào $tq"
  local last; last=$(ls -t /tmp/sc_*.lock "$tq"/sc_*.lock 2>/dev/null | head -1)
  [ -n "$last" ] && say "  Lần gần nhất backdoor 'sc_' chạy (file khoá mới nhất): $(stat -c '%y' "$last" | cut -c1-19)"

  say "== Chặn máy chủ C2 trong /etc/hosts"
  for h in "${C2_HOSTS[@]}"; do
    if grep -qE "^[0-9.]+\s+$h" /etc/hosts; then say "  đã chặn: $h"
    elif isfix; then echo "0.0.0.0 $h" >> /etc/hosts; say "  -> đã chặn $h"
    else say "  [CHƯA CHẶN] $h"; fi
  done

  say "== Đăng nhập root gần đây & key SSH (tự đối chiếu xem có IP lạ không)"
  last -n 15 2>/dev/null | sed 's/^/  /' | tee -a "$LOG"
  [ -f /root/.ssh/authorized_keys ] && awk '{print "  key: " $NF}' /root/.ssh/authorized_keys | tee -a "$LOG"
  local ww; ww=$(find "$LSWS"/*/html -maxdepth 1 -perm -o+w -type d 2>/dev/null | wc -l)
  if [ "$ww" -gt 0 ]; then
    say "== [CẢNH BÁO] $ww thư mục web để quyền 777: site này ghi được vào site kia, mã độc sẽ lây chéo."
    isfix && say "   -> Chế độ fix sẽ tự đưa về 755/644 (wp-config 600) khi xử lý từng site WordPress, giữ nguyên chủ sở hữu." \
          || say "   -> Chạy 'fix' để tự sửa, hoặc sửa tay: find /usr/local/lsws/*/html -type d -perm -0002 -exec chmod 755 {} +"
    [ -n "$ONLY" ] && say "   -> Đang chạy cho 1 site. Trên server này NÊN chạy 'fix' cho TOÀN BỘ site (bỏ tên domain)."
  fi
  isfix && { mkdir -p "$Q"; chmod 700 "$Q"; say "== Thư mục cách ly: $Q"; }
}

# ---------------------------------------------------------------- quét backdoor (dùng 2 lần: trong lúc dọn và sau khi restart PHP)
DROPINS=" advanced-cache.php object-cache.php db.php db-error.php install.php maintenance.php sunrise.php blog-deleted.php blog-inactive.php blog-suspended.php fatal-error-handler.php php-error.php index.php "
DROPIN_LEGIT='WP Rocket|WP_ROCKET|LiteSpeed|LSCWP|W3 ?Total|W3TC|Query Monitor|QM_DB|WP Super Cache|wpsc|Cache Enabler|Breeze|SiteGround|Hummingbird|WP Fastest|Swift Performance|Comet Cache|HyperDB|LudicrousDB|redis|memcache|Docket|Object Cache Pro|Atec'
sweep_backdoors() {
  local WC=$1 f d b rel
  # 3a) Drop-in trong wp-content/ (db.php, object-cache.php...) — được nạp TRƯỚC mọi plugin,
  #     hacker dùng db.php để tự tạo lại backdoor trong mu-plugins
  for f in "$WC"/*.php; do
    b=$(basename "$f")
    if grep -qE "$SIG_BACKDOOR|$SIG_INJECT|$SIG_OBF|function[[:space:]]+ego[[:space:]]*\(" "$f" 2>/dev/null \
       || { [ "$(stat -c %Y "$f")" -ge "$CUTOFF" ] && grep -qE "$SIG_WEAK" "$f"; }; then
      qmove drop-in-doc "$f"
    elif grep -qE 'wpanel|class-wp-locale-(data|switch)|_wp_locale_pack|wp-locale-cache|\.wp-object-cache-|\.sc_|\.oc_' "$f" 2>/dev/null \
         || { [[ " db.php advanced-cache.php object-cache.php " == *" $b "* ]] && [ "$(stat -c %s "$f")" -lt 2000 ] \
              && ! grep -qiE "$DROPIN_LEGIT" "$f" 2>/dev/null; }; then
      qmove drop-in-doc "$f"                               # drop-in giả cỡ nhỏ (vd 408/496 byte) nạp wpanel / backdoor "sc_"
    elif grep -qE "$SIG_WEAK" "$f" 2>/dev/null; then
      review "drop-in cũ có base64/eval, cần xem: ${f#"$LSWS"/}"
    elif [ "$b" != index.php ] && [ "$(stat -c %Y "$f")" -ge "$CUTOFF" ] && grep -qE '(include|require)(_once)?' "$f" \
         && ! grep -qiE 'litespeed|w3 ?total|redis|memcache|query monitor|wp rocket|hyperdb|ludicrousdb' "$f"; then
      qmove drop-in-doc "$f"
    elif [[ $DROPINS != *" $b "* ]]; then
      review "file PHP lạ trong wp-content/: ${f#"$LSWS"/}"
    fi
  done
  # 3a2) Zip tên hex 8 ký tự trong uploads/YYYY/MM chứa PHP (gói backdoor index-importer-pad)
  for f in "$WC"/uploads/20*/*/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].zip; do
    [ -f "$f" ] && unzip -l "$f" 2>/dev/null | grep -qE 'index-importer-pad|\.php$' && qmove goi-ma-doc "$f"
  done
  # 3b) Thư mục / file ẩn của backdoor
  while IFS= read -r -d '' f; do qmove ban-sao-an "$f"
  done < <(find "$WC" -maxdepth 3 \( -name '.sc_*' -o -name '.oc_*' -o -name '.q_*' -o -name '.sd_*' -o -name '.rd_*' -o -name '.wr_*' -o -name '.gk_*' -o -name '.kk_*' -o -name '.swm_*' -o -name '.bt_*' -o -name '.wp-object-cache-*.dat*' \) -prune -print0 2>/dev/null)
  # 3b2) Mã độc "wpanel agent": file nạp trong mu-plugins + phần thân giấu ở languages/upgrade/cache/.wpanel
  for f in "$WC/languages/class-wp-locale-data.php" "$WC/upgrade/class-wp-locale-data.php" \
           "$WC/cache/class-wp-locale-data.php" "$WC/languages/class-wp-locale-switch.php" \
           "$WC/upgrade/class-wp-locale-switch.php" "$WC/cache/class-wp-locale-switch.php" "$WC/.wpanel"; do qmove wpanel-agent "$f"; done
  while IFS= read -r f; do qmove wpanel-agent "$f"
  done < <(grep -rlE --include='*.php' -D skip 'wpanel_agent' "$WC/languages" "$WC/upgrade" "$WC/cache" "$WC/uploads" 2>/dev/null)
  for f in "$WC"/themes/*/functions.php "$WC"/plugins/*/*.php; do
    grep -qF 'wpanel_agent' "$f" 2>/dev/null && ! grep -qF '// WPANEL:BEGIN' "$f" && review "có gọi wpanel_agent (cần cắt tay): ${f#"$LSWS"/}"
  done
  # 3c) Backdoor index-importer-pad + mọi bản sao có dấu SCV
  qmove backdoor "$WC/plugins/index-importer-pad"
  qmove backdoor "$WC/mu-plugins/index-importer-pad.php"
  while IFS= read -r f; do
    [ -e "$f" ] || continue
    rel=${f#"$WC"/}
    case "$rel" in
      plugins/*/*) qmove backdoor "$WC/plugins/$(cut -d/ -f2 <<<"$rel")" ;;
      *)           qmove backdoor "$f" ;;
    esac
  done < <(find "$WC/plugins" "$WC/mu-plugins" "$WC/themes" -maxdepth 2 -type f -name '*.php' -size +300k 2>/dev/null \
             | xargs -r -d '\n' grep -l '/\* SCV:[0-9]' 2>/dev/null)


  # 3d) mu-plugins: WordPress tự nạp mọi file .php ở đây mà không cần kích hoạt -> soát kỹ
  local MU="$WC/mu-plugins" sub qsubs=()
  # .htaccess trong mu-plugins (thường để mở quyền gọi thẳng webshell)
  [ -f "$MU/.htaccess" ] && qmove mu-plugin-doc "$MU/.htaccess"
  # thư mục con: chứa PHP có dấu webshell, hoặc tên ngẫu nhiên tạo sau ngày nhiễm
  for sub in "$MU"/*/; do sub=${sub%/}; b=$(basename "$sub")
    if grep -rlqE --include='*.php' "$SIG_BACKDOOR|$SIG_INJECT|$SIG_OBF" "$sub" 2>/dev/null \
       || { [ "$(stat -c %Y "$sub")" -ge "$CUTOFF" ] && grep -rlqE --include='*.php' "$SIG_WEAK" "$sub"; }; then
      qmove mu-plugin-doc "$sub"; qsubs+=("$b")
    elif [[ $b =~ ^[a-z0-9]{5,8}$ && $b =~ [0-9] ]] \
         || { [[ $b =~ ^[a-z]{5,8}$ ]] && { [ "$(stat -c %Y "$sub")" -ge "$CUTOFF" ] || [ "$(stat -c %Z "$sub")" -ge "$CUTOFF" ]; }; } \
         || grep -rlqE --include='*.php' "$SIG_WEAK" "$sub" 2>/dev/null; then
      # tên ngẫu nhiên lẫn số (iwarq1g, dau1xt) / tên ngẫu nhiên mới (kể cả bị giả ngày: xét cả ctime) / có eval-base64
      qmove mu-plugin-doc "$sub"; qsubs+=("$b")
    else
      review "thư mục con trong mu-plugins: ${sub#"$LSWS"/}"
    fi
  done
  # file .php: dấu backdoor/webshell, hoặc nạp file từ thư mục con vừa bị cách ly
  for f in "$MU"/*.php; do
    local loader=0 s
    for s in "${qsubs[@]}"; do grep -qF "$s" "$f" 2>/dev/null && loader=1; done
    # file nạp hàng loạt thư mục con (glob(__DIR__ ...) + require), tạo sau ngày nhiễm
    [ "$(stat -c %Y "$f")" -ge "$CUTOFF" ] && grep -qE 'glob\(' "$f" && grep -qE '(include|require)(_once)?' "$f" && loader=1
    if grep -qE "$SIG_BACKDOOR|$SIG_INJECT|$SIG_OBF" "$f" 2>/dev/null || [ $loader = 1 ] \
       || { [ "$(stat -c %Y "$f")" -ge "$CUTOFF" ] && grep -qE "$SIG_WEAK" "$f"; }; then qmove mu-plugin-doc "$f"
    elif grep -qE "$SIG_WEAK" "$f" 2>/dev/null; then review "mu-plugin cũ có base64/eval, cần xem: ${f#"$LSWS"/}"
    elif [ "$(stat -c %Y "$f")" -ge "$CUTOFF" ]; then
      review "mu-plugin tạo/sửa sau $INFECT_DATE: ${f#"$LSWS"/} ($(stat -c %s "$f") byte) — $(grep -m1 -oE '(include|require)(_once)?[^;]{0,80}' "$f")"
    fi
  done
  for d in "$WC"/plugins/*/; do d=${d%/}
    local pf=("$d"/*.php)
    [ ${#pf[@]} -gt 0 ] && grep -lqE "$SIG_BACKDOOR" "${pf[@]}" 2>/dev/null && qmove plugin-doc "$d"
    b=$(basename "$d")
    # plugin "Protect Uploads" giả: thư mục tên ngẫu nhiên chứa protect-uploads.php (vỏ bọc webshell BYTE_BUNK...)
    [ -e "$d" ] && [ -f "$d/protect-uploads.php" ] && [ "$b" != protect-uploads ] && qmove plugin-gia "$d"
    # php.ini/.user.ini trong plugin (mở lại exec/shell_exec cho webshell)
    [ -e "$d" ] && for f in "$d/php.ini" "$d/.user.ini"; do [ -f "$f" ] && grep -qiE 'disable_functions|shell_exec|safe_mode|open_basedir' "$f" && qmove php-ini "$f"; done
    [ -e "$d" ] && [[ $b =~ ^[A-Za-z0-9]{6,8}$ && $b =~ [A-Z] && $b =~ [a-z] ]] && [ ! -f "$d/readme.txt" ] \
      && review "plugin tên ngẫu nhiên, không có readme: ${d#"$LSWS"/}"
  done

}


# ---------------------------------------------------------------- soát toàn bộ cấu trúc site theo danh sách cho phép
ROOT_OK=" wp-admin wp-includes wp-content .htaccess .htaccess.bk license.txt readme.html .tmb .well-known robots.txt favicon.ico ads.txt app-ads.txt "
WC_OK=" plugins themes uploads mu-plugins languages upgrade upgrade-temp-backup cache litespeed index.php advanced-cache.php object-cache.php db.php wflogs ai1wm-backups updraft backups-dup-lite backups-dup-pro et-cache fonts w3tc-config wp-rocket-config maintenance.php debug.log .htaccess wpo-cache webp-express ewww jetpack-waf boost-cache .litespeed_conf.dat leagues.json setting.json smush-webp wp-cloudflare-super-page-cache ew-backup "
audit_structure() {
  local H=$1 WC="$1/wp-content" e b f n

  # A) .htaccess mở quyền chạy PHP ở bất kỳ thư mục con nào
  while IFS= read -r -d '' f; do
    [ "$f" = "$H/.htaccess" ] && continue
    grep -qiE "$HT_OPEN" "$f" && grep -qiE 'php' "$f" && qmove htaccess-mo-php "$f"
  done < <(find "$H" -name .htaccess -type f -print0 2>/dev/null)

  # B) Thứ lạ ở gốc web (thư mục / file ẩn không thuộc WordPress)
  for e in "$H"/* "$H"/.[!.]*; do
    [ -e "$e" ] || continue; b=$(basename "$e")
    # bản sao wp-config do WPTT tạo: giữ lại nhưng chặn web tải về (lộ mật khẩu DB) -> chỉ chủ site đọc được
    if [[ $b == wp-config.php.backup.* ]]; then
      if [ -n "$(find "$e" -maxdepth 0 -perm -o+r 2>/dev/null)" ]; then
        if isfix; then chmod 600 "$e"; CNT[lo-cau-hinh]=$(( ${CNT[lo-cau-hinh]:-0} + 1 )); else review "bản sao wp-config ai cũng đọc được (tải qua web được): ${e#"$LSWS"/}"; fi
      fi; continue; fi
    [[ $ROOT_OK == *" $b "* || $CORE_ROOT == *" $b "* || $b == *.QUARANTINE ]] && continue
    if [ -d "$e" ]; then
      if find "$e" -name '*.php' -print -quit 2>/dev/null | grep -q . && \
         { [ "$(stat -c %Y "$e")" -ge "$CUTOFF" ] || grep -rlqE --include='*.php' "$SIG_OBF|$SIG_BACKDOOR" "$e"; }
      then qmove thu-muc-la "$e"
      else review "thư mục lạ ở gốc web: ${e#"$LSWS"/}"; fi
    elif [[ $b =~ ^wp-config.+ && $b != wp-config.php && $b != wp-config-sample.php ]]; then
      qmove lo-cau-hinh "$e"                               # bản sao wp-config (.bak/.backup/.old...) web đọc được -> lộ mật khẩu DB
    elif [[ $b =~ ^wp-[a-z-]+\.(gz|zip|tar|tgz|bz2)$ ]]; then
      qmove goi-ma-doc "$e"                                # file nén nhái tên core (vd wp-slgnup.gz)
    elif [[ $b =~ ^google[0-9a-f]{16}\.html$ ]]; then
      if [ "$(stat -c %Y "$e")" -ge "$CUTOFF" ]; then
        if [[ " $GOOGLE_KEEP " == *" ${b:6:16} "* ]]; then review "file xác minh Google của bạn (GOOGLE_KEEP), giữ lại: ${e#"$LSWS"/}"
        else qmove google-gia "$e"; fi                     # hacker tự xác minh Search Console của họ
      fi
    elif [[ $b != *.php ]]; then
      [ "$(stat -c %Y "$e")" -ge "$CUTOFF" ] && review "file lạ ở gốc web (tạo/sửa sau $INFECT_DATE): ${e#"$LSWS"/}"
    fi
  done

  # C) Thứ lạ trong wp-content/
  for e in "$WC"/* "$WC"/.[!.]*; do
    [ -e "$e" ] || continue; b=$(basename "$e")
    [[ $WC_OK == *" $b "* || $b == *.QUARANTINE ]] && continue
    [ -f "$e" ] && [[ $b == *.php ]] && continue          # drop-in .php đã soát ở bước trước
    if [ -d "$e" ]; then
      if find "$e" -name '*.php' -print -quit 2>/dev/null | grep -q . && \
         { [[ $b =~ ^\.?[a-z]{5,8}$ ]] || [ "$(stat -c %Y "$e")" -ge "$CUTOFF" ] || grep -rlqE --include='*.php' "$SIG_OBF|$SIG_BACKDOOR" "$e"; }
      then qmove thu-muc-la "$e"
      else review "thư mục lạ trong wp-content: ${e#"$LSWS"/} — $(find "$e" -type f | wc -l) file"; fi
    elif [[ $b =~ ^[0-9a-f]{8}\.(zip|gz|tar|tgz)$ ]]; then
      qmove goi-ma-doc "$e"                                # gói mã độc tên hex ngẫu nhiên (vd dd10b3e6.zip)
    elif [[ $b =~ ^\.?sc_[0-9a-f]{16,40}\.(lock|dat|tmp|json)$ ]]; then
      qmove dau-vet-sc "$e"                                # file khoá/trạng thái của backdoor họ "sc_" (SCV/SC_TH)
    else
      review "file lạ trong wp-content: ${e#"$LSWS"/}"
    fi
  done

  # D) File PHP làm rối kiểu webshell ở bất kỳ đâu (plugin, theme, languages, upgrade, cache...)
  #    Dấu hiệu mạnh -> cách ly. Dấu hiệu yếu -> chỉ cách ly nếu file tạo/sửa sau ngày nhiễm, còn lại CẦN XEM.
  while IFS= read -r f; do qmove php-lam-roi "$f"
  done < <(timeout 900 grep -rlE -D skip --include='*.php' --exclude-dir=node_modules "$SIG_OBF" "$WC" 2>/dev/null | grep -vE '/_quarantine_|\.l10n\.php$')
  while IFS= read -r f; do
    [ -e "$f" ] || continue
    if [ "$(stat -c %Y "$f")" -ge "$CUTOFF" ]; then qmove php-lam-roi "$f"
    else review "có eval(\$bien(...)) nhưng file cũ, cần xem: ${f#"$LSWS"/}"; fi
  done < <(timeout 900 grep -rlE -D skip --include='*.php' --exclude-dir=node_modules "$SIG_OBF_WEAK" "$WC" 2>/dev/null | grep -vE '/_quarantine_|\.l10n\.php$')

  # E) Danh sách mọi file bị tạo/sửa từ ngày nhiễm (bỏ ảnh trong uploads, cache) để tự soát
  find "$H" \( -path "$WC/cache" -o -path "$WC/litespeed" \) -prune -o -type f -newermt "$INFECT_DATE" \
       ! \( -path "$WC/uploads/*" ! -name '*.php' \) -printf '%TY-%Tm-%Td %TH:%TM %10s %p\n' 2>/dev/null \
       | sed "s|$LSWS/||" | sort > "$OUT/sites/$S.changed.txt"
  n=$(wc -l < "$OUT/sites/$S.changed.txt")
  [ "$n" -gt 0 ] && say "  [DANH SÁCH]  $n file tạo/sửa từ $INFECT_DATE -> $OUT/sites/$S.changed.txt"
}

# ---------------------------------------------------------------- xử lý 1 site
# Chạy lệnh dưới quyền user của site; hỗ trợ cả uid không có tên (UNKNOWN)
asu() {
  if [ "$UID_" = 0 ]; then echo "  [BỎ QUA] thư mục site thuộc root — không chạy wp-cli dưới root" >&2; return 1; fi
  if getent passwd "$UID_" >/dev/null; then runuser -u "$(getent passwd "$UID_" | cut -d: -f1)" -- "$@"
  else setpriv --reuid="$UID_" --regid="$GID_" --clear-groups -- "$@"; fi
}

process_site() {
  local S=$1 H="$LSWS/$1/html" WC U G f d b rel V vc n
  WC="$H/wp-content"
  [ -f "$H/wp-includes/version.php" ] || [ -d "$WC" ] || return 1
  U=$(stat -c %U "$H"); G=$(stat -c %G "$H")   # user/group riêng của site theo WPTT
  UID_=$(stat -c %u "$H"); GID_=$(stat -c %g "$H")   # dùng số: không lỗi khi user đã bị xoá khỏi /etc/passwd (UNKNOWN)
  LOG="$OUT/sites/$S.log"; : > "$LOG"
  CNT=(); SEEN=()
  say "=== $S  (user: $U:$G)"

  step "quét webshell"
  # 1) Webshell theo md5 (toàn bộ site, trừ cache)
  while IFS= read -r -d '' f; do is_shell_md5 "$f" && qmove webshell "$f"
  done < <(find "$H" \( -path "$WC/cache" -o -path "$WC/litespeed" -o -name node_modules \) -prune \
             -o -type f -name '*.php' -size 10676c -print0 2>/dev/null)

  # 2) Thư mục well-known giả + đồ đã đổi tên .QUARANTINE từ lần dọn tay trước
  for d in "$H/well-known" "$WC/well-known"; do qmove well-known-gia "$d"; done
  while IFS= read -r -d '' f; do qmove da-khoa-truoc "$f"
  done < <(find "$H" -maxdepth 6 -name '*.QUARANTINE' -prune -print0 2>/dev/null)

  # 3-5) Drop-in độc, bản sao ẩn, backdoor (làm trước tiên để giảm thời gian mã độc kịp tự cài lại)
  sweep_backdoors "$WC"

  step "file lẻ, php.ini"
  # 6) File lẻ đặt thẳng trong plugins/ và themes/ (lndex.php, functions.php, widget.area.*.php...)
  for f in "$WC"/plugins/*.php "$WC"/themes/*.php; do
    b=$(basename "$f")
    [ "$b" = index.php ] && [ "$(stat -c %s "$f")" -lt 200 ] && continue
    [ "$b" = hello.php ] && ! grep -qE "$SIG_BACKDOOR|$SIG_INJECT|$SIG_WEAK" "$f" && continue
    qmove file-le "$f"
  done
  for d in "$WC"/themes/widget*area*; do qmove file-le "$d"; done

  # 7) php.ini / .user.ini tắt bảo mật
  for f in "$H/php.ini" "$H/.user.ini" "$WC/php.ini" "$WC/.user.ini" "$H/wp-admin/php.ini" "$H/wp-admin/.user.ini"; do
    [ -f "$f" ] || continue
    if grep -qiE 'disable_functions[[:space:]]*=[[:space:]]*(none)?[[:space:]]*$|auto_prepend|shell_exec|safe_mode|open_basedir[[:space:]]*=[[:space:]]*off' "$f"
    then qmove php-ini "$f"; else review "${f#"$LSWS"/}: $(tr '\n' ' ' < "$f" | cut -c1-120)"; fi
  done

  # 7b) Mã PHP giấu dạng base64 trong file .txt ở uploads (PD9waHA = "<?php"), thư mục wpanel, .tmb của File Manager
  while IFS= read -r -d '' f; do head -c 7 "$f" | grep -q '^PD9waHA' && qmove goi-ma-doc "$f"
  done < <(find "$WC/uploads" -maxdepth 2 -type f -name '*.txt' -print0 2>/dev/null)
  qmove wpanel-agent "$WC/uploads/wp-locale-cache"
  qmove file-le "$H/.tmb"

  step "quét PHP trong uploads"
  # 8) File PHP trong uploads (bình thường không được có)
  while IFS= read -r -d '' f; do
    [ "$(basename "$f")" = index.php ] && [ "$(stat -c %s "$f")" -lt 200 ] && continue
    qmove php-trong-uploads "$f"
  done < <(find "$WC/uploads" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[3-8]' -o -iname '*.phar' \) -print0 2>/dev/null)

  step "soát toàn bộ cấu trúc site (thư mục lạ, .htaccess mở quyền, file làm rối)"
  audit_structure "$H"

  step "tìm mã cấy trong theme/plugin"
  # 9) Mã bị cấy vào theme / plugin -> cắt đoạn mã, giữ file
  # Theme mặc định của WordPress (twentytwenty*) bị cấy mã hoặc gọi wpanel -> cài lại bản sạch từ wordpress.org
  if isfix && [ -n "$WP" ]; then
    for d in "$WC"/themes/twenty*/; do d=${d%/}
      grep -rlqE --include='*.php' "$SIG_INJECT|$SIG_BACKDOOR|$SIG_OBF" "$d" 2>/dev/null || continue
      b=$(basename "$d"); V=$(grep -m1 -oP '^Version:\s*\K\S+' "$d/style.css" 2>/dev/null)
      rel=${d#"$LSWS"/}; mkdir -p "$Q/$(dirname "$rel")"; cp -a "$d" "$Q/$rel.orig" 2>/dev/null
      if timeout 300 "$WP" theme install "$b" ${V:+--version="$V"} --force --path="$H" --allow-root --skip-plugins --skip-themes >>"$LOG" 2>&1; then
        chown -R "$UID_:$GID_" "$d"; CNT[theme-cai-lai]=$(( ${CNT[theme-cai-lai]:-0} + 1 )); say "  [SỬA]       theme $b bị cấy mã -> đã cài lại bản sạch ${V:-mới nhất} từ wordpress.org"
      else say "  [LỖI]        cài lại theme $b thất bại, sẽ cắt mã thủ công"; fi
    done
  fi
  mapfile -t inj < <(timeout 900 grep -rlE -D skip --exclude-dir=node_modules --exclude-dir=.git --include='*.php' "$SIG_INJECT" "$WC/themes" "$WC/plugins" 2>/dev/null)
  if [ ${#inj[@]} -gt 0 ]; then
    CNT[ma-cay-vao-file]=${#inj[@]}
    if isfix; then
      for f in "${inj[@]}"; do rel=${f#"$LSWS"/}; mkdir -p "$Q/$(dirname "$rel")"; cp -p "$f" "$Q/$rel.orig"; done
      python3 "$OUT/clean_inject.py" --apply "${inj[@]}" | tee -a "$LOG"
    else
      python3 "$OUT/clean_inject.py" --dry "${inj[@]}" | tee -a "$LOG"
    fi
  fi

  # 10) File PHP lạ ở gốc web (webshell tên ngẫu nhiên, wp-cron-xxxx.php...)
  for f in "$H"/*.php "$H"/.*.php; do
    b=$(basename "$f")
    case "$CORE_ROOT" in *" $b "*) continue;; esac
    if [ ! -s "$f" ] || grep -qE "$SIG_BACKDOOR|$SIG_INJECT|$SIG_WEAK" "$f" 2>/dev/null || [[ $b =~ ^wp-cron-[a-z0-9]{4}\.php$ ]]
    then qmove php-la-goc-web "$f"
    else review "file PHP lạ ở gốc web (không có dấu hiệu độc): ${f#"$LSWS"/}"; fi
  done

  step "cài lại core WordPress (tải từ wordpress.org)"
  # 11) Core WordPress: cài lại bản sạch + cách ly file thừa
  V=$(grep -oP "wp_version\s*=\s*'\K[^']+" "$H/wp-includes/version.php" 2>/dev/null)
  if [ -n "$WP" ] && [ -f "$H/wp-includes/version.php" ]; then
    if isfix; then
      if timeout 600 "$WP" core download --force --skip-content ${V:+--version="$V"} --path="$H" --allow-root --quiet >>"$LOG" 2>&1
      then say "  [CORE]       đã cài lại WordPress ${V:-mới nhất}"; CNT[core-cai-lai]=1
      else say "  [LỖI]        tải core WordPress $V thất bại"; CNT[loi-core]=1; fi
      chown -R "$UID_:$GID_" "$H/wp-admin" "$H/wp-includes"
      for b in $CORE_ROOT; do [ -f "$H/$b" ] && [ "$b" != wp-config.php ] && chown "$UID_:$GID_" "$H/$b"; done
    fi
    vc=$(timeout 300 "$WP" core verify-checksums ${V:+--version="$V"} --path="$H" --allow-root 2>&1)
    while IFS= read -r f; do [ -n "$f" ] && qmove core-file-thua "$H/$f"
    done < <(sed -n 's/^Warning: File should not exist: //p' <<<"$vc")
    n=$(grep -c "doesn't verify against checksum" <<<"$vc")
    [ "$n" -gt 0 ] && { CNT[core-bi-sua]=$n; say "  [PHÁT HIỆN] (core-bi-sua) $n file core sai checksum"; }
    if isfix; then n=$(find "$H/wp-admin" "$H/wp-includes" -mindepth 1 -type d -empty 2>/dev/null | wc -l)
      [ "$n" -gt 0 ] && { find "$H/wp-admin" "$H/wp-includes" -mindepth 1 -type d -empty -delete 2>/dev/null; say "  [SỬA]       xoá $n thư mục rỗng lạ trong wp-admin/wp-includes (vỏ còn lại của mã độc)"; }; fi
    grep -q "doesn't exist" <<<"$vc" && say "  [PHÁT HIỆN] (core-thieu) $(grep -c "doesn't exist" <<<"$vc") file core bị xoá"
  else
    [ -z "$WP" ] && say "  [BỎ QUA]     không có wp-cli, không kiểm tra/cài lại core"
  fi
  if [ ! -s "$H/index.php" ]; then
    CNT[index-trang]=1
    if isfix; then
      printf "<?php\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n" > "$H/index.php"
      chown "$UID_:$GID_" "$H/index.php"; say "  [SỬA]       index.php trắng -> đã ghi lại bản chuẩn"
    else say "  [PHÁT HIỆN] (index-trang) index.php 0 byte -> site trắng"; fi
  fi

  # 12) .htaccess
  f="$H/.htaccess"
  if [ -f "$f" ] && grep -qiE "$HT_BAD" "$f"; then
    CNT[htaccess-doc]=1
    say "  [PHÁT HIỆN] (htaccess-doc) $(grep -niE "$HT_BAD" "$f" | head -3 | tr '\n' ' ')"
    if isfix; then
      rel=${f#"$LSWS"/}; mkdir -p "$Q/$(dirname "$rel")"; cp -p "$f" "$Q/$rel.bad"
      if [ -f "$H/.htaccess.bk" ] && ! grep -qiE "$HT_BAD" "$H/.htaccess.bk" && [ "$(stat -c %Y "$H/.htaccess.bk")" -lt "$CUTOFF" ]; then
        cp "$H/.htaccess.bk" "$f"; say "  [SỬA]       .htaccess -> khôi phục từ .htaccess.bk"
      else
        printf '# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %%{REQUEST_FILENAME} !-f\nRewriteCond %%{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n' > "$f"
        say "  [SỬA]       .htaccess -> ghi lại bản WordPress mặc định"
      fi
      chown "$UID_:$GID_" "$f"
    fi
  fi
  # 12b) Thiếu luật rewrite của WordPress -> mọi trang con 404 (trang 404 của LiteSpeed)
  if ! grep -qE 'RewriteRule[[:space:]]+\.[[:space:]]+/index\.php' "$f" 2>/dev/null; then
    CNT[htaccess-thieu-rewrite]=1
    if isfix; then
      [ -f "$f" ] && { rel=${f#"$LSWS"/}; mkdir -p "$Q/$(dirname "$rel")"; cp -p "$f" "$Q/$rel.truoc-them-rewrite"; }
      printf '\n# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %%{REQUEST_FILENAME} !-f\nRewriteCond %%{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n' >> "$f"
      chown "$UID_:$GID_" "$f"; say "  [SỬA]       .htaccess thiếu luật rewrite WordPress -> đã thêm (trang con hết 404)"
    else say "  [PHÁT HIỆN] (htaccess-thieu-rewrite) .htaccess không có luật rewrite -> trang con sẽ 404"; fi
  fi
  grep -niE 'RewriteRule[^#]*https?://' "$f" 2>/dev/null | grep -vi 'HTTP_HOST' | head -3 | while read -r l; do review ".htaccess chuyển hướng ra ngoài: $l"; done
  for f in "$WC/.htaccess" "$WC/uploads/.htaccess"; do
    [ -f "$f" ] && grep -qiE "$HT_BAD" "$f" && qmove htaccess-doc "$f"
  done

  # 13) wp-config.php (chỉ báo, không tự sửa)
  grep -qE "$SIG_BACKDOOR|$SIG_INJECT|$SIG_WEAK|@include|include[^;]*\.(ico|png|jpg|gif|txt)" "$H/wp-config.php" 2>/dev/null \
    && review "wp-config.php có đoạn đáng ngờ: $(grep -nE "$SIG_BACKDOOR|$SIG_INJECT|$SIG_WEAK|@include" "$H/wp-config.php" | head -2 | cut -c1-120)"

  step "soát admin"
  # 14) Admin mới tạo từ ngày nhiễm (chỉ khi fix, chạy bằng user site, không dùng root)
  if isfix && [ -n "$WP" ] && id "$U" >/dev/null 2>&1; then
    asu timeout 120 env HOME=/tmp "$WP" user list --role=administrator \
      --fields=ID,user_login,user_email,user_registered --format=csv \
      --skip-plugins --skip-themes --path="$H" > "$OUT/sites/$S.admins.csv" 2>/dev/null
    awk -F, -v c="$INFECT_DATE" 'NR>1 { d=$4; gsub(/"/,"",d); if (d>=c || d<"2000") print }' "$OUT/sites/$S.admins.csv" 2>/dev/null | while read -r l; do
      review "admin đáng ngờ (tạo sau $INFECT_DATE hoặc ngày giả trước 2000): $l"; done
  fi

  # 14a) Payload giấu trong database: option "optimizer" (mu-plugin wp-cache-optimizer đọc rồi chạy)
  if isfix && [ -n "$WP" ] && id "$U" >/dev/null 2>&1; then
    local opt
    opt=$(asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes option get optimizer 2>/dev/null)
    if [ -n "$opt" ]; then
      mkdir -p "$Q/$S"; printf '%s' "$opt" > "$Q/$S/option-optimizer.b64"
      asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes option delete optimizer >/dev/null 2>&1
      CNT[db-payload]=1; say "  [SỬA]       xoá option 'optimizer' trong database (mã độc dạng base64, bản lưu: _quarantine_.../$S/option-optimizer.b64)"
    fi
    # WP-cron của mã độc (sc_cron_recovery / sc_cron_fetch cài lại plugin wp-compat, tạo admin root_*)
    local ev
    ev=$(asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes cron event list --field=hook 2>/dev/null | grep -E '^sc_' | sort -u | tr '\n' ' ')
    if [ -n "$ev" ]; then
      asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes cron event delete $ev >/dev/null 2>&1
      CNT[db-payload]=1; say "  [SỬA]       xoá WP-cron của mã độc: $ev"
    fi
    # Token đăng nhập cửa hậu của mu-plugin sso-loader
    asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes option delete sso_token >/dev/null 2>&1 \
      && { CNT[db-payload]=1; say "  [SỬA]       xoá option 'sso_token' (cửa hậu đăng nhập không cần mật khẩu)"; }
    # Bài deface
    local dp
    dp=$(asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes post list --post_type=any --post_status=any --s='Hacked By' --field=ID 2>/dev/null | tr '\n' ' ')
    if [ -n "${dp// /}" ]; then
      if isfix; then
        mkdir -p "$Q/$S"
        asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes post list --post_type=any --post_status=any \
          --post__in="$(echo $dp | tr ' ' ',')" --fields=ID,post_author,post_date,post_status,post_title --format=csv > "$Q/$S/deface-posts.csv" 2>/dev/null
        asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes post delete $dp --force >/dev/null 2>&1
        CNT[deface]=1; say "  [SỬA]       xoá bài viết deface 'Hacked By' (ID: $dp) — tác giả bài là tài khoản bị chiếm, ĐỔI MẬT KHẨU admin"
      else CNT[deface]=1; say "  [PHÁT HIỆN] (deface) bài viết 'Hacked By' ID: $dp"; fi
    fi
    # Gỡ plugin đã bị cách ly khỏi danh sách active_plugins
    asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes eval '$a=(array)get_option("active_plugins");$b=array_values(array_filter($a,function($p){return file_exists(WP_PLUGIN_DIR."/".$p);}));if($a!==$b){update_option("active_plugins",$b);echo "  [SỬA]       bỏ khỏi active_plugins: ".implode(", ",array_diff($a,$b))."\n";}' 2>/dev/null | tee -a "$LOG"
  fi

  step "soát quyền 777 và nội dung bị deface"
  # 14b) Quyền ghi cho mọi người (777/666) -> ai cũng sửa được file. Chuẩn: thư mục 755, file 644, wp-config 600
  n=$(find "$H" -perm -o+w ! -type l 2>/dev/null | wc -l)
  if [ "$n" -gt 0 ]; then
    CNT[quyen-777]=$n
    if isfix; then
      find "$H" -type d -perm -o+w -exec chmod 755 {} + 2>/dev/null
      find "$H" -type f -perm -o+w -exec chmod 644 {} + 2>/dev/null
      chmod 600 "$H/wp-config.php" 2>/dev/null
      say "  [SỬA]       $n file/thư mục để quyền ghi cho mọi người (777/666) -> đã đưa về 755/644, wp-config 600"
    else say "  [PHÁT HIỆN] (quyen-777) $n file/thư mục ai cũng ghi được"; fi
  fi
  # 14c) Deface trong database: bài/trang/template có chữ "hacked by", link t.me... (chỉ báo, không tự sửa)
  if isfix && [ -n "$WP" ] && id "$U" >/dev/null 2>&1; then
    asu timeout 120 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes eval '
      global $wpdb;
      $rows = $wpdb->get_results("SELECT ID,post_type,post_status,post_modified,post_title FROM $wpdb->posts
        WHERE post_status IN ("publish","private","draft") AND (post_content REGEXP "[Hh]acked [Bb]y|t\\.me/|Hack_0x|<iframe[^>]+display: *none"
        OR post_title REGEXP "[Hh]acked [Bb]y")");
      foreach ($rows as $r) echo "POST $r->ID|$r->post_type|$r->post_modified|$r->post_title
";
      foreach (array("blogname","blogdescription") as $o) { $v = get_option($o); if (preg_match("/hacked by/i", $v)) echo "OPTION $o|$v
"; }
    ' 2>/dev/null | while IFS= read -r l; do review "nội dung nghi bị deface trong database: $l"; done
  fi

  step "soát quyền sở hữu"
  # 15) Soát quyền sở hữu: mọi file của site phải thuộc user riêng của site
  if isfix; then
    n=$(find "$H/wp-content" -maxdepth 1 -user root 2>/dev/null | wc -l)
    [ "$n" -gt 0 ] && { find "$H/wp-content" -maxdepth 1 -user root -exec chown "$UID_:$GID_" {} + 2>/dev/null; say "  [SỬA]       $n thư mục trong wp-content thuộc root (vd mu-plugins) -> trả về $U"; }
  fi
  n=$(find "$H" ! -user "$U" 2>/dev/null | wc -l)
  [ "$n" -gt 0 ] && review "$n file/thư mục KHÔNG thuộc user $U, vd: $(find "$H" ! -user "$U" 2>/dev/null | head -3 | sed "s|$LSWS/||" | tr '\n' ' ')"

  # Tổng kết site
  local sum="" k
  for k in $(printf '%s\n' "${!CNT[@]}" | sort); do sum+="$k=${CNT[$k]} "; done
  [ -z "$sum" ] && sum="sạch"
  echo "$S|$U|$sum" >> "$OUT/summary.raw"
  say "  => $sum"
  return 0
}

# ---------------------------------------------------------------- harden
# set_ini <file> <key> <value>: sửa dòng có sẵn (kể cả đang bị ; comment) hoặc thêm mới
set_ini() {
  local ini=$1 key=$2 val=$3 k
  k=$(printf '%s' "$key" | sed 's/\./\\./g')
  if grep -qE "^[[:space:]]*;?[[:space:]]*$k[[:space:]]*=" "$ini"; then
    sed -i -E "s|^[[:space:]]*;?[[:space:]]*$k[[:space:]]*=.*|$key = $val|" "$ini"
  else
    printf '\n%s = %s\n' "$key" "$val" >> "$ini"
  fi
}
harden() {
  LOG="$OUT/global.log"
  local DF="exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec,pcntl_fork,proc_nice,proc_terminate,proc_get_status,dl"
  local ini cur new found=0
  say "== Bật disable_functions cho lsphp (PHP chạy web). wp-cli/WPTT được giữ nguyên qua php-cli.ini nếu cần"
  for ini in "$LSWS"/lsphp*/etc/php/*/litespeed/php.ini "$LSWS"/lsphp*/etc/php.ini; do
    found=1
    cp -p "$ini" "$ini.bak-$TS"
    cur=$(grep -oP '^\s*disable_functions\s*=\s*\K.*' "$ini" | head -1 | tr -d '" ')
    new=$(printf '%s,%s' "$cur" "$DF" | tr ',' '\n' | grep -v '^$' | sort -u | paste -sd, -)
    if grep -qE '^\s*disable_functions\s*=' "$ini"; then
      sed -i -E "s|^\s*disable_functions\s*=.*|disable_functions = $new|" "$ini"
    else echo "disable_functions = $new" >> "$ini"; fi
    say "  $ini"; say "    -> disable_functions = $new   (bản cũ: $ini.bak-$TS)"
    # Chặn lợi dụng session upload progress (ghi dữ liệu tuỳ ý vào file session -> LFI thành RCE)
    set_ini "$ini" session.upload_progress.enabled Off
    say "    -> session.upload_progress.enabled = Off"
    # Nếu PHP dòng lệnh (wp-cli, WPTT) cũng đọc file này -> tạo php-cli.ini bên cạnh (PHP CLI ưu tiên
    # php-cli.ini hơn php.ini) với disable_functions để trống, để wp-cli/WPTT không bị chặn proc_open.
    local bin="${ini%%/etc/*}/bin/php" cli="$(dirname "$ini")/php-cli.ini"
    if [ -x "$bin" ] && "$bin" --ini 2>/dev/null | grep -qF "$ini"; then
      if [ ! -f "$cli" ] || head -1 "$cli" | grep -q 'wp-incident-fix'; then
        { echo "; tạo bởi wp-incident-fix.sh: cấu hình cho PHP dòng lệnh (wp-cli/WPTT), không chặn hàm"; cat "$ini"; } > "$cli"
        set_ini "$cli" disable_functions ""
        say "    -> PHP dòng lệnh dùng chung file này: đã tạo $cli để wp-cli/WPTT vẫn chạy bình thường"
      else
        say "    [CẦN XEM] đã có $cli của bạn -> kiểm tra wp-cli có bị chặn proc_open không"
      fi
    fi
  done
  [ $found = 0 ] && say "  Không tìm thấy php.ini của lsphp trong $LSWS"
  for h in "${C2_HOSTS[@]}"; do grep -qE "^[0-9.]+\s+$h" /etc/hosts || { echo "0.0.0.0 $h" >> /etc/hosts; say "  -> đã chặn $h"; }; done
  pkill -9 lsphp 2>/dev/null
  say "Đã khởi động lại lsphp. Kiểm tra: tạo file <?php var_dump(function_exists('shell_exec')); trong 1 site, kết quả phải là false."
}

# ---------------------------------------------------------------- php2shell (CVE-2026-109618 / CVE-2026-109619)
# Bản vá PHP 21/10/2026: 8.2.35, 8.3.36, 8.4.27, 8.5.12. 8.1 trở xuống: PHP không phát hành bản vá.
P2S_RED=$'\033[1;31m'; P2S_GRN=$'\033[1;32m'; P2S_YEL=$'\033[1;33m'; P2S_OFF=$'\033[0m'
p2s_fixed_for() { case $1 in 82) echo 8.2.35;; 83) echo 8.3.36;; 84) echo 8.4.27;; 85) echo 8.5.12;; *) echo "";; esac; }
p2s_ver() { local d=$1 b; for b in "$d/bin/php" "$d/bin/lsphp"; do [ -x "$b" ] && { "$b" -n -r 'echo PHP_VERSION;' 2>/dev/null && return; }; done; echo "?"; }
p2s_ok() { local v=$1 f=$2; [ -n "$f" ] && [ "$v" != "?" ] && [ "$(printf '%s\n%s\n' "$f" "${v%%-*}" | sort -V | head -1)" = "$f" ]; }
p2s_sites() {   # site dùng lsphpXX: khai báo trong vhconf, hoặc mọi site nếu server chỉ có 1 bản lsphp
  local l; l=$(grep -lE "lsphp$1([^0-9]|$)" "$LSWS"/conf/vhosts/*/vhconf.conf 2>/dev/null | awk -F/ '{print $(NF-1)}' | paste -sd' ' -)
  if [ -z "$l" ] && [ "$(ls -d "$LSWS"/lsphp[0-9][0-9] 2>/dev/null | wc -l)" = 1 ]; then ls -d "$LSWS"/*/html 2>/dev/null | awk -F/ '{print $(NF-1)}' | paste -sd' ' -; else echo "$l"; fi; }

php2shell() {
  LOG="$OUT/php2shell.log"; : > "$LOG"
  local PKGLOG="$OUT/php2shell-pkg.log" d n v f pm rc failed=0 vuln=0 dirs=() before=()
  say "== Vá PHP2Shell (CVE-2026-109618, CVE-2026-109619) cho lsphp — log: $LOG, log gói: $PKGLOG"
  for d in "$LSWS"/lsphp[0-9][0-9]; do [ -d "$d" ] && dirs+=("$d"); done
  [ ${#dirs[@]} -gt 0 ] || { say "${P2S_RED}[LỖI] Không thấy thư mục $LSWS/lsphpXX nào${P2S_OFF}"; return 1; }

  say "-- Phiên bản hiện tại:"
  for d in "${dirs[@]}"; do n=${d##*lsphp}; v=$(p2s_ver "$d"); before+=("$v")
    say "   lsphp$n  $v   (bản vá: $(f=$(p2s_fixed_for "$n"); echo "${f:-không có, đã hết hỗ trợ}"))  site dùng: $(p2s_sites "$n" | wc -w)"; done

  # 1) Cập nhật gói lsphp từ repo LiteSpeed
  # Ubuntu/Debian có thể có lệnh "dnf" giả (bí danh của apt) -> xét hệ điều hành trước
  if [ -f /etc/debian_version ] && command -v apt-get >/dev/null; then pm=apt
  elif command -v dnf >/dev/null && [ -f /etc/redhat-release ]; then pm=dnf
  elif command -v yum >/dev/null; then pm=yum
  elif command -v apt-get >/dev/null; then pm=apt; fi
  say "-- Cập nhật gói lsphp bằng ${pm:-?} ..."
  case $pm in
    dnf|yum)
      $pm clean expire-cache >>"$PKGLOG" 2>&1
      $pm -y update 'lsphp*' >>"$PKGLOG" 2>&1; rc=$? ;;
    apt)
      { apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade $(dpkg-query -W -f='${Package}\n' 'lsphp*' 2>/dev/null | paste -sd' ' -); } >>"$PKGLOG" 2>&1; rc=$? ;;
    *) rc=127; echo "không tìm thấy dnf/yum/apt-get" >>"$PKGLOG" ;;
  esac
  if [ "$rc" != 0 ]; then
    failed=1
    say "${P2S_RED}[LỖI CẬP NHẬT] $pm thoát với mã $rc. 30 dòng cuối của log:${P2S_OFF}"
    tail -30 "$PKGLOG" | sed 's/^/   | /' | tee -a "$OUT/global.log"
    say "${P2S_YEL}   Gợi ý: kiểm tra repo LiteSpeed ('$pm repolist' / 'ls /etc/yum.repos.d/ | grep -i litespeed'), mạng ra ngoài, dung lượng đĩa (df -h).${P2S_OFF}"
  else
    say "   $pm chạy xong (rc=0)"
    grep -iE 'Upgraded|Upgrading|Nâng cấp|Complete|Nothing to do|0 upgraded' "$PKGLOG" | tail -5 | sed 's/^/   | /'
  fi

  # 2) Khởi động lại toàn bộ worker PHP để nạp bản mới
  pkill -9 lsphp 2>/dev/null; "$LSWS/bin/lswsctrl" restart >>"$PKGLOG" 2>&1 || say "${P2S_RED}[LỖI] lswsctrl restart thất bại (xem $PKGLOG)${P2S_OFF}"

  # 3) Kiểm tra lại từng bản; bản chưa vá -> giảm thiểu bằng php.ini
  say "-- Kết quả sau cập nhật:"
  local i=0 ini
  for d in "${dirs[@]}"; do n=${d##*lsphp}; v=$(p2s_ver "$d"); f=$(p2s_fixed_for "$n")
    if p2s_ok "$v" "$f"; then
      say "   ${P2S_GRN}[ĐÃ VÁ]${P2S_OFF}   lsphp$n  ${before[$i]} -> $v"
    else
      vuln=1
      if [ -z "$f" ]; then
        say "   ${P2S_RED}[KHÔNG CÓ BẢN VÁ]${P2S_OFF} lsphp$n $v — PHP 8.1 trở xuống đã hết hỗ trợ. Chuyển các site sau sang lsphp83/84: $(p2s_sites "$n")"
      else
        say "   ${P2S_RED}[CHƯA VÁ]${P2S_OFF}  lsphp$n  $v < $f — repo LiteSpeed chưa có bản mới hoặc cập nhật lỗi. Chạy lại lệnh này sau."
      fi
      for ini in "$d"/etc/php/*/litespeed/php.ini "$d"/etc/php.ini; do [ -f "$ini" ] || continue
        cp -p "$ini" "$ini.bak-p2s-$TS"
        set_ini "$ini" session.upload_progress.enabled Off
        [ "$n" = 85 ] && set_ini "$ini" fatal_error_backtraces Off
        [ "${P2S_OPCACHE_OFF:-0}" = 1 ] && set_ini "$ini" opcache.enable 0
        [ "${P2S_MEMLIMIT:-0}" = 1 ] && set_ini "$ini" memory_limit -1
        say "      -> giảm thiểu tạm trong $ini: session.upload_progress.enabled=Off$([ "$n" = 85 ] && echo ', fatal_error_backtraces=Off')$([ "${P2S_OPCACHE_OFF:-0}" = 1 ] && echo ', opcache.enable=0')$([ "${P2S_MEMLIMIT:-0}" = 1 ] && echo ', memory_limit=-1')"
        local chk; chk=$("$d/bin/php" -c "$ini" -r 'echo ini_get("session.upload_progress.enabled") ? "On" : "Off";' 2>&1)
        [ "$chk" = Off ] || say "      ${P2S_RED}[LỖI] session.upload_progress vẫn là '$chk' sau khi sửa $ini${P2S_OFF}"
      done
    fi
    i=$((i+1))
  done
  [ $vuln = 1 ] && { pkill -9 lsphp 2>/dev/null; "$LSWS/bin/lswsctrl" restart >>"$PKGLOG" 2>&1; }
  say ""
  if [ $failed = 0 ] && [ $vuln = 0 ]; then say "${P2S_GRN}XONG: mọi lsphp đã lên bản vá PHP2Shell.${P2S_OFF}"
  elif [ $vuln = 0 ]; then say "${P2S_GRN}AN TOÀN: mọi lsphp đã ở bản vá PHP2Shell.${P2S_OFF} ${P2S_YEL}Riêng lệnh cập nhật gói bị lỗi (xem trên) -> sửa để lần sau cập nhật được.${P2S_OFF}"; return 0
  else say "${P2S_YEL}CHƯA XONG: còn lsphp chưa vá (xem trên). Giảm thiểu tạm đã bật; chỉ cập nhật PHP mới vá triệt để.${P2S_OFF}"
       say "   Tuỳ chọn giảm thiểu thêm (có thể ảnh hưởng hiệu năng): P2S_OPCACHE_OFF=1 P2S_MEMLIMIT=1 bash $0 php2shell"; fi
  return $(( failed || vuln ))
}

# ---------------------------------------------------------------- restore
restore() {
  local run=$1 cat=${2:-} dom=${3:-} line c rel dst n=0
  [ -d "$run/sites" ] || { echo "Không thấy $run/sites"; exit 1; }
  for log in "$run"/sites/${dom:-*}.log; do
    grep -h '\[CÁCH LY\]' "$log" | while IFS= read -r line; do
      c=$(sed -E 's/.*\[CÁCH LY\][[:space:]]+\(([^)]*)\).*/\1/' <<<"$line")
      [ -n "$cat" ] && [ "$c" != "$cat" ] && continue
      rel=$(sed -E 's/.*\) ([^ ]+).*/\1/' <<<"$line")
      dst=$(sed -nE 's/.*==> (.*)$/\1/p' <<<"$line")
      [ -z "$dst" ] && dst="_quarantine_${run##*wp-incident-}/$rel"
      if [ -e "$LSWS/$rel" ]; then echo "  BỎ QUA (đã có file ở chỗ cũ): $rel"
      elif mv -n -T "$LSWS/$dst" "$LSWS/$rel" 2>/dev/null; then echo "  ĐÃ TRẢ LẠI ($c) $rel"
      else echo "  LỖI: không thấy $LSWS/$dst"; fi
    done
  done
  pkill -9 lsphp 2>/dev/null
}

# ---------------------------------------------------------------- admins
ADMIN_PHP='
global $wpdb;
$cut = getenv("CUT"); $apply = getenv("APPLY") === "1";
$keep = array_filter(preg_split("/[\\s,]+/", (string) getenv("KEEP")));
$key = $wpdb->get_blog_prefix() . "capabilities";
$rows = $wpdb->get_results($wpdb->prepare(
  "SELECT u.ID,u.user_login,u.user_email,u.user_registered FROM {$wpdb->users} u
   JOIN {$wpdb->usermeta} m ON m.user_id=u.ID AND m.meta_key=%s
   WHERE m.meta_value LIKE %s ORDER BY u.user_registered, u.ID", $key, "%administrator%"));
$bad = array(); $good = array();
foreach ($rows as $r) { $d = substr($r->user_registered, 0, 10);
  if (in_array($r->user_login, $keep, true)) { $r->keep = 1; $good[] = $r; }
  elseif ($d >= $cut || $d < "2000-01-01") $bad[] = $r; else $good[] = $r; }
foreach ($good as $r) echo "  GIỮ   #$r->ID $r->user_login ($r->user_registered)" . (isset($r->keep) ? " [KEEP_ADMINS]" : "") . "\n";
foreach ($bad as $r)  echo "  ĐỘC   #$r->ID $r->user_login $r->user_email ($r->user_registered)\n";
if ($apply) foreach ($good as $r) if (isset($r->keep)) {
  $pw = wp_generate_password(20, false); wp_set_password($pw, $r->ID);
  echo "  [ĐỔI MẬT KHẨU] $r->user_login  =>  $pw\n"; }
if (!$apply || !$bad) return;
if (!$good) { echo "  [BỎ QUA] không còn admin hợp lệ nào để nhận bài viết -> xử lý tay site này\n"; return; }
require_once ABSPATH . "wp-admin/includes/user.php";
$to = $good[0]->ID;
foreach ($bad as $r) echo wp_delete_user($r->ID, $to) ? "  [ĐÃ XOÁ] $r->user_login (bài viết chuyển cho #$to)\n" : "  [LỖI XOÁ] $r->user_login\n";
WP_Session_Tokens::destroy_all_for_all_users();
echo "  [ĐĂNG XUẤT] mọi phiên đăng nhập\n";
'
admins_mode() {
  local apply=$1 s H U out; out="$OUT/admins.txt"; : > "$out"
  [ -n "$WP" ] || { echo "Cần wp-cli"; exit 1; }
  local sites=()
  if [ -n "$ONLY" ]; then sites=("$ONLY"); else for d in "$LSWS"/*/html; do s=$(basename "$(dirname "$d")"); [[ $s == _* ]] || sites+=("$s"); done; fi
  for s in "${sites[@]}"; do
    H="$LSWS/$s/html"; [ -f "$H/wp-config.php" ] || continue
    U=$(stat -c %U "$H"); UID_=$(stat -c %u "$H"); GID_=$(stat -c %g "$H")
    echo "=== $s" | tee -a "$out"
    asu timeout 120 env HOME=/tmp CUT="$INFECT_DATE" APPLY="$apply" KEEP="$KEEP_ADMINS" "$WP" --path="$H" \
      --skip-plugins --skip-themes eval "$ADMIN_PHP" 2>&1 | grep -vE '^(PHP )?(Warning|Notice|Deprecated)' | tee -a "$out"
    if [ "$apply" = 1 ] && grep -q "ĐÃ XOÁ" <(tail -50 "$out"); then
      asu timeout 60 env HOME=/tmp "$WP" --path="$H" --skip-plugins --skip-themes config shuffle-salts >/dev/null 2>&1 \
        && echo "  [SALT] đã đổi" | tee -a "$out"
    fi
  done
  echo; echo "Tổng: $(grep -c '  ĐỘC' "$out") admin độc trên $(grep -c '^===' "$out") site   |   Chi tiết: $out"
  [ "$apply" = 1 ] || echo "Đây mới là LIỆT KÊ. Kiểm tra cột GIỮ/ĐỘC rồi chạy: bash $0 admins-apply ${ONLY}"
  [ "$apply" = 1 ] && grep -q 'ĐỔI MẬT KHẨU' "$out" && { awk '/^===/{s=$2} /ĐỔI MẬT KHẨU/{print s, $4, $6}' "$out" > "$OUT/admin-pass.txt"; chmod 600 "$OUT/admin-pass.txt"; echo "Mật khẩu mới của KEEP_ADMINS: $OUT/admin-pass.txt"; }
  [ "$apply" = 1 ] && echo "Xong. Admin GIỮ lại nên đặt mật khẩu mới (Quên mật khẩu) vì mật khẩu cũ đã bị lộ."
}

# ================================================================= MAIN
# ---------------------------------------------------------------- all: chạy trọn quy trình 1 lượt
if [ "$MODE" = all ]; then
  ALLLOG="$OUT/all.log"
  R=$'\033[1;31m' G=$'\033[1;32m' Y=$'\033[1;33m' B=$'\033[1;36m' N=$'\033[0m'
  declare -a RES
  run_step() {   # run_step <số> <tên hiển thị> <mode> [domain]
    local no=$1 name=$2 m=$3 t0=$SECONDS rc
    echo; echo "${B}################ BƯỚC $no/4: $name  ($(date +%T))${N}" | tee -a "$ALLLOG"
    OUT="$OUT/$no-$m" bash "$0" "$m" ${4:+"$4"} 2>&1 | tee -a "$ALLLOG"; rc=${PIPESTATUS[0]}
    if [ "$rc" = 0 ]; then RES+=("${G}[OK]${N}    Bước $no $name ($((SECONDS-t0))s)  -> $OUT/$no-$m")
    else RES+=("${R}[LỖI $rc]${N} Bước $no $name ($((SECONDS-t0))s)  -> xem $OUT/$no-$m"); fi
  }
  echo "${B}== Chạy trọn quy trình: php2shell -> fix (gồm harden) -> admins -> admins-apply${ONLY:+  | chỉ site: $ONLY}${N}" | tee "$ALLLOG"
  echo "   Log tổng: $ALLLOG   |   KEEP_ADMINS=\"$KEEP_ADMINS\"" | tee -a "$ALLLOG"
  run_step 1 "Vá PHP2Shell"                       php2shell
  run_step 2 "Dọn mã độc + harden + cách ly"      fix          "$ONLY"
  run_step 3 "Liệt kê admin GIỮ/ĐỘC"              admins       "$ONLY"
  if [ "${SKIP_ADMINS_APPLY:-0}" = 1 ]; then RES+=("${Y}[BỎ QUA]${N} Bước 4 xoá admin độc (SKIP_ADMINS_APPLY=1)")
  else run_step 4 "Xoá admin độc + đổi mật khẩu KEEP_ADMINS" admins-apply "$ONLY"; fi
  { echo; echo "${B}################ TỔNG KẾT ($(date +%T))${N}"; printf '  %s\n' "${RES[@]}"
    f=$(ls "$OUT"/2-fix/summary.txt 2>/dev/null) && { echo; echo "  Site lỗi/trắng sau khi dọn:"; e=$(grep 'SITE LỖI' "$f"); [ -n "$e" ] && echo "$e" | sed 's/^/    /' || echo "    (không có)"; }
    p=$(ls "$OUT"/4-admins-apply/admin-pass.txt 2>/dev/null) && echo "  Mật khẩu mới (adminhp...): $p"
    echo "  Cần xem tay: grep -h 'CẦN XEM' $OUT/2-fix/sites/*.log | less"
    echo "  Sau 1-2 giờ chạy: bash $0 check   -> xác nhận mã độc không mọc lại"
  } | tee -a "$ALLLOG"
  printf '%s\n' "${RES[@]}" | grep -q 'LỖI' && exit 1 || exit 0
fi

if [ "$MODE" = php2shell ]; then php2shell; exit $?; fi
if [ "$MODE" = harden ]; then harden; exit 0; fi
if [ "$MODE" = restore ]; then restore "$2" "${3:-}" "${4:-}"; exit 0; fi
if [ "$MODE" = admins ]; then admins_mode 0; exit 0; fi
if [ "$MODE" = admins-apply ]; then admins_mode 1; exit 0; fi

write_cleaner
if isfix && [ "${NO_HARDEN:-0}" != 1 ]; then
  say "== Bật disable_functions TRƯỚC khi dọn để PHP web không sinh lại tiến trình ngầm (đặt NO_HARDEN=1 để bỏ qua)"
  harden
fi
global_pre

SITES=()
if [ -n "$ONLY" ]; then SITES=("$ONLY")
else for d in "$LSWS"/*/html; do s=$(basename "$(dirname "$d")"); [[ $s == _* ]] || SITES+=("$s"); done; fi

i=0
for s in "${SITES[@]}"; do
  i=$((i+1)); echo ">>> [$i/${#SITES[@]}] $s"
  process_site "$s" || echo "    (bỏ qua: không phải site WordPress)"
done

LOG="$OUT/global.log"
if isfix; then
  rm -rf "$LSWS"/cachedata/* 2>/dev/null
  # Xoá cache trang của plugin (WP Rocket, WP Super Cache, LiteSpeed...): trang HTML đã lưu có thể còn chứa mã độc cũ
  say "== Xoá cache trang HTML của plugin (wp-content/cache, litespeed) để không phát lại trang nhiễm"
  for d in "$LSWS"/*/html/wp-content/cache "$LSWS"/*/html/wp-content/litespeed; do
    [ -d "$d" ] && find "$d" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null
  done
  pkill -9 lsphp 2>/dev/null
  say "== Kill tiến trình lạ lần cuối"; kill_site_procs
  [ -x "$LSWS/bin/lswsctrl" ] && "$LSWS/bin/lswsctrl" reload >/dev/null 2>&1 && say "== Đã reload LiteSpeed để đọc lại .htaccess"
  sleep 3
  # Vòng 2: mã độc có thể đã tự cài lại trong lúc đang dọn -> quét backdoor lần nữa
  say "== Vòng 2: quét lại backdoor sau khi khởi động lại PHP"
  while IFS='|' read -r s u sum; do
    LOG="$OUT/sites/$s.log"; CNT=(); SEEN=()
    echo "  --- vòng 2 ---" >> "$LOG"
    sweep_backdoors "$LSWS/$s/html/wp-content"
    unset 'CNT[can-xem]'
    if [ ${#CNT[@]} -gt 0 ]; then
      LOG="$OUT/global.log"; say "  [VÒNG 2] $s: ${!CNT[*]} -> đã cách ly thêm"
      sed -i "s~^$s|$u|~$s|$u|vong2-moc-lai=${#CNT[@]} ~" "$OUT/summary.raw"
    fi
  done < "$OUT/summary.raw"
  LOG="$OUT/global.log"
  kill_site_procs
  pkill -9 lsphp 2>/dev/null; sleep 2
fi

say ""
say "############ KẾT QUẢ"
{
  printf '%-34s %-9s %s\n' "SITE" "HTTP" "PHÁT HIỆN / ĐÃ XỬ LÝ"
  while IFS='|' read -r s u sum; do
    h=$(http_check "$s"); set -- $h
    # PHP vừa khởi động lại có thể còn trả lỗi vài giây -> thử lại sau 8s
    if [ "$1" = 000 ] || [ "$1" -ge 500 ] || { [ "$1" = 200 ] && [ "$2" -lt 500 ]; }; then
      sleep 8; h=$(http_check "$s"); set -- $h
    fi
    flag=""
    { [ "$1" = 000 ] || [ "$1" -ge 500 ] || { [ "$1" = 200 ] && [ "$2" -lt 500 ]; }; } && flag=" <-- SITE LỖI/TRẮNG"
    printf '%-34s %-9s %s%s\n' "$s" "$1/$2" "$sum" "$flag"
  done < "$OUT/summary.raw"
} | tee "$OUT/summary.txt" | tee -a "$LOG"

say ""
say "Báo cáo: $OUT/summary.txt   |   Log từng site: $OUT/sites/"
isfix && say "File đã cách ly: $Q   (chỉ root đọc được; khôi phục bằng mv ngược lại)"
isfix && say "Site có mã độc và ĐÃ được dọn trong lần chạy này: $(grep -vcE '\|sạch$|\|can-xem=[0-9]+ $' "$OUT/summary.raw" 2>/dev/null)/$(wc -l < "$OUT/summary.raw")   (chạy 'check' để xác nhận đã sạch)"
isfix || say "Site còn mã độc: $(grep -vcE '\|sạch$|\|can-xem=[0-9]+ $' "$OUT/summary.raw" 2>/dev/null)/$(wc -l < "$OUT/summary.raw")   |   Cần xem tay: grep -h 'CẦN XEM' $OUT/sites/*.log"
if isfix; then
  say ""
  say "VIỆC CÒN LẠI:"
  say " 1) Chạy lại: bash $0 check   -> phải ra 'sạch' hết (trừ mục cần xem)."
  say " 2) bash $0 harden            -> tắt exec/shell_exec cho PHP web."
  say " 3) Đổi mật khẩu MỌI admin WP + salt wp-config + mật khẩu root/SSH (mã đánh cắp mật khẩu đã chạy)."
fi
