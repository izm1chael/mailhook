#!/bin/sh
set -e

# Determine whether this is a full removal or an upgrade.
# deb calls preremove with "remove"/"purge" on removal, "upgrade" on upgrade.
# rpm calls preremove with 0 on last removal, 1 on upgrade.
IS_REMOVAL=0
case "$1" in
    remove|purge|abort-install) IS_REMOVAL=1 ;;
    0) IS_REMOVAL=1 ;;  # rpm: 0 = last removal
esac

if [ "$IS_REMOVAL" = "1" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop  mailhook.service 2>/dev/null || true
    systemctl disable mailhook.service 2>/dev/null || true
fi
