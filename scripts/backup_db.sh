#!/bin/bash

BACKUP_DIR="/var/backups/whispera"
RETENTION_DAYS=7
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/whispera/backup.log"

mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

if [ -f "/etc/whispera/postgres.env" ]; then
    source /etc/whispera/postgres.env
else
    log "Error: /etc/whispera/postgres.env not found!"
    exit 1
fi

if ! command -v pg_dump &> /dev/null; then
    log "Error: pg_dump not found!"
    exit 1
fi

FILENAME="$BACKUP_DIR/whispera_backup_$DATE.sql.gz"
log "Starting backup: $FILENAME"

export PGPASSWORD=$POSTGRES_PASSWORD

if pg_dump -h localhost -U $POSTGRES_USER -d $POSTGRES_DB | gzip > "$FILENAME"; then
    log "Backup created successfully: $(du -h "$FILENAME" | cut -f1)"
else
    log "Backup failed!"
    rm -f "$FILENAME"
    exit 1
fi

log "Cleaning up old backups (keeping latest 5)..."
ls -1t "$BACKUP_DIR"/whispera_backup_*.sql.gz 2>/dev/null | tail -n +6 | xargs -r rm -f

log "Backup process completed."
