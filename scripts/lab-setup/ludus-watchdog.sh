#!/bin/bash
# Ludus VM watchdog — restarts critical VMs if they go down.
# Runs every 60s via cron.
PATH=/usr/sbin:/usr/local/sbin:/sbin:/usr/bin:/bin

LOG=/var/log/lab-watchdog.log
[ -f "$LOG" ] && [ $(wc -l < "$LOG") -gt 1000 ] && mv "$LOG" "${LOG}.old"

# VMIDs of VMs that should always be running
VMS="107 108 113 114"  # router, DC01, Win11, kali

for vmid in $VMS; do
    state=$(qm status "$vmid" 2>/dev/null | awk '{print $2}')
    if [ "$state" != "running" ]; then
        echo "[$(date)] VM $vmid state=$state, starting..." >> "$LOG"
        qm start "$vmid" >> "$LOG" 2>&1
    fi
done
