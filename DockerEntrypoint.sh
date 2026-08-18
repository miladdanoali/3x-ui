#!/bin/sh

# Start fail2ban with the 3x-ipl jail
if [ "$XUI_ENABLE_FAIL2BAN" = "true" ]; then
    LOG_FOLDER="${XUI_LOG_FOLDER:-/var/log/x-ui}"
    mkdir -p "$LOG_FOLDER"
    touch "$LOG_FOLDER/3xipl.log" "$LOG_FOLDER/3xipl-banned.log"

    mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d /etc/fail2ban/action.d

    cat > /etc/fail2ban/jail.d/3x-ipl.conf << EOF
[3x-ipl]
enabled=true
backend=auto
filter=3x-ipl
action=3x-ipl
logpath=$LOG_FOLDER/3xipl.log
maxretry=1
findtime=32
bantime=30m
EOF

    cat > /etc/fail2ban/filter.d/3x-ipl.conf << 'EOF'
[Definition]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
failregex   = \[LIMIT_IP\]\s*Email\s*=\s*<F-USER>.+</F-USER>\s*\|\|\s*Disconnecting OLD IP\s*=\s*<ADDR>\s*\|\|\s*Timestamp\s*=\s*\d+
ignoreregex =
EOF

    # Ports to exempt from the ban
    SSH_PORTS=$(grep -oE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | grep -oE '[0-9]+' | paste -sd, -)
    [ -z "$SSH_PORTS" ] && SSH_PORTS="22"
    PANEL_PORT=$(/app/x-ui setting -show true 2>/dev/null | grep -Eo 'port: .+' | awk '{print $2}')
    EXEMPT_PORTS="$SSH_PORTS"
    [ -n "$PANEL_PORT" ] && EXEMPT_PORTS="$EXEMPT_PORTS,$PANEL_PORT"

    cat > /etc/fail2ban/action.d/3x-ipl.conf << EOF
[INCLUDES]
before = iptables-allports.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -j f2b-<name>

actionstop = <iptables> -D <chain> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban = <iptables> -I f2b-<name> 1 -s <ip> -p tcp -m multiport ! --dports <exemptports> -j <blocktype>
            <iptables> -I f2b-<name> 1 -s <ip> -p udp -m multiport ! --dports <exemptports> -j <blocktype>
            echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   BAN   [Email] = <F-USER> [IP] = <ip> banned for <bantime> seconds." >> $LOG_FOLDER/3xipl-banned.log

actionunban = <iptables> -D f2b-<name> -s <ip> -p tcp -m multiport ! --dports <exemptports> -j <blocktype>
              <iptables> -D f2b-<name> -s <ip> -p udp -m multiport ! --dports <exemptports> -j <blocktype>
              echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   UNBAN   [Email] = <F-USER> [IP] = <ip> unbanned." >> $LOG_FOLDER/3xipl-banned.log

[Init]
name = default
chain = INPUT
exemptports = $EXEMPT_PORTS
EOF

    fail2ban-client -x start
fi

# Certificate auto-renewal
if [ -f /root/.acme.sh/acme.sh ]; then
    /root/.acme.sh/acme.sh --install-cronjob >/dev/null 2>&1
    crond
fi

# ========================================================
# تغییرات جدید: سیستم مسیرساز Nginx
# ========================================================

# ۱. ساخت کانفیگ Nginx برای تفکیک ترافیک
cat > /etc/nginx/nginx.conf << 'EOF'
events {}
http {
    server {
        listen 2053;
        
        # هدایت مسیر اصلی به پنل مدیریت سنایی (پورت ۲۰۵۴)
        location / {
            proxy_pass http://127.0.0.1:2054;
            proxy_set_header Host $host;
        }

        # هدایت مسیر /tunnel به کانکفیگ VLESS (پورت ۸۴۴۳)
        location /tunnel {
            proxy_pass http://127.0.0.1:8443;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
        }

        # هدایت مسیر /sub برای لینک‌های سابسکریپشن (پورت ۲۰۵۵)
        location /sub {
            proxy_pass http://127.0.0.1:2055;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
EOF

# ۲. اجرای Nginx در پس‌زمینه
nginx

# ۳. انتقال پنل مدیریت به پورت ۲۰۵۴ تا پورت ۲۰۵۳ برای Nginx آزاد شود
/app/x-ui setting -port 2054

# تنظیم رمز و نام کاربری پیش‌فرض
/app/x-ui setting -username admin -password admin

# اجرای تونل سریع کلودفلر و هدایت خروجی به تب Logs در داشبورد
/usr/bin/cloudflared tunnel --url http://127.0.0.1:2053 2>&1 &

# اجرای هسته اصلی پنل
exec /app/x-ui
