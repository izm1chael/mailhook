#!/bin/sh
set -e

# Create the mailhook system user if it doesn't exist.
if ! id -u mailhook >/dev/null 2>&1; then
    useradd \
        --system \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --user-group \
        mailhook
fi

# Ensure runtime directories exist with correct ownership.
install -d -o mailhook -g mailhook -m 750 \
    /var/lib/mailhook \
    /var/lib/mailhook/emls \
    /var/lib/mailhook/rules \
    /var/cache/mailhook \
    /var/cache/mailhook/feeds \
    /etc/mailhook

# Lock down config files so only root and the mailhook group can read secrets.
chown root:mailhook /etc/mailhook/mailhook.env /etc/mailhook/config.yaml 2>/dev/null || true
chmod 640 /etc/mailhook/mailhook.env /etc/mailhook/config.yaml 2>/dev/null || true

# Reload systemd, enable services.
# The guard prevents failures in minimal containers / chroot installs.
if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running --quiet 2>/dev/null; then
    systemctl daemon-reload

    # Rspamd
    systemctl enable rspamd.service  >/dev/null 2>&1 || true
    systemctl start  rspamd.service  2>/dev/null || true

    # ClamAV — kick off virus database download before starting the daemon.
    # freshclam can take a few minutes on first run.
    if command -v freshclam >/dev/null 2>&1; then
        systemctl enable clamav-freshclam.service >/dev/null 2>&1 || true
        systemctl start  clamav-freshclam.service 2>/dev/null || true
    fi
    systemctl enable clamav-daemon.service >/dev/null 2>&1 || true
    # clamd will start automatically once freshclam finishes the first DB download.
    systemctl start  clamav-daemon.service 2>/dev/null || true

    # MailHook itself
    systemctl enable mailhook.service >/dev/null 2>&1 || true
fi

echo ""
echo "MailHook installed. Next steps:"
echo ""
echo "  1. Edit IMAP accounts:  /etc/mailhook/config.yaml"
echo "  2. Edit env / secrets:  /etc/mailhook/mailhook.env"
echo "     - Set MAILHOOK_ADMIN_PASSWORD_BCRYPT  (run: make setup-password)"
echo "     - Set MAILHOOK_CSRF_SECRET            (run: openssl rand -hex 32)"
echo "     - Set MAILHOOK_DB_ENCRYPTION_KEY      (run: openssl rand -hex 32)"
echo "  3. Start MailHook:      systemctl start mailhook"
echo "  4. Check logs:          journalctl -u mailhook -f"
echo ""
echo "  Note: ClamAV will download its virus database in the background (~300 MB)."
echo "  MailHook will show ClamAV as unavailable until freshclam completes."
echo ""
