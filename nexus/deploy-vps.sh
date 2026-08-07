#!/usr/bin/env bash
# Stands up nexus (Neo4j, Redis, the API, and the Telegram bot) on a fresh
# Debian/Ubuntu VPS as systemd-managed services that survive reboots and
# restart on crash.
#
# Run this ON THE SERVER, as root, over your own SSH session:
#   curl -fsSL https://raw.githubusercontent.com/raulpanim/Neo/claude/nexus-bring-up-repair-cbbj70/nexus/deploy-vps.sh | bash
# or clone the repo yourself and run it from nexus/.
#
# Safe to re-run: installs are skipped if already present, the graph is
# only seeded if empty, systemd units are just overwritten and reloaded.
set -euo pipefail

REPO_URL="https://github.com/raulpanim/Neo.git"
BRANCH="claude/nexus-bring-up-repair-cbbj70"
INSTALL_DIR="/opt/nexus"

say() { printf '\n\033[0;32m▸ %s\033[0m\n' "$1"; }
die() { printf '\n\033[0;31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this as root."

# --- Docker -------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  say "Installing Docker"
  curl -fsSL https://get.docker.com | sh
fi
command -v docker >/dev/null 2>&1 || die "Docker install failed."

# --- Node.js 20+ ----------------------------------------------------------
node_major() { node -v 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/'; }
if ! command -v node >/dev/null 2>&1 || [ "$(node_major)" -lt 20 ] 2>/dev/null; then
  say "Installing Node.js 20"
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi
command -v git >/dev/null 2>&1 || apt-get install -y git

# --- Fetch the app --------------------------------------------------------
if [ -d "$INSTALL_DIR/.git" ]; then
  say "Updating existing checkout"
  git -C "$INSTALL_DIR" fetch origin "$BRANCH"
  git -C "$INSTALL_DIR" checkout "$BRANCH"
  git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
else
  say "Cloning nexus"
  git clone --branch "$BRANCH" --single-branch "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR/nexus"

# --- Configuration ---------------------------------------------------------
[ -f .env ] || cp .env.example .env

if ! grep -q '^TELEGRAM_BOT_TOKEN=.\+' .env; then
  die "Set TELEGRAM_BOT_TOKEN in $INSTALL_DIR/nexus/.env (get one from
@BotFather on Telegram), then re-run this script.
While you're in there: API_KEY locks down the API before you ever expose
port 3000 publicly, and TELEGRAM_ALERT_CHAT_ID turns on push alerts."
fi

# --- Neo4j + Redis (loopback-only per docker-compose.yml) ------------------
say "Starting Neo4j and Redis"
docker compose up -d neo4j redis

say "Waiting for Neo4j"
for i in $(seq 1 60); do
  docker exec nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass 'RETURN 1' >/dev/null 2>&1 && break
  [ "$i" -eq 60 ] && die "Neo4j did not come up. Check: docker compose logs neo4j"
  sleep 1
done

say "Waiting for Redis"
for i in $(seq 1 30); do
  docker exec nexus-redis redis-cli ping >/dev/null 2>&1 && break
  [ "$i" -eq 30 ] && die "Redis did not come up. Check: docker compose logs redis"
  sleep 1
done

# --- App dependencies + data ------------------------------------------------
say "Installing dependencies"
npm ci

say "Loading schema and seed data (only if the graph is empty)"
COUNT="$(docker exec nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass --format plain 'MATCH (n) RETURN count(n)' | tail -1)"
if [ "${COUNT:-0}" = "0" ]; then
  docker exec -i nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass < db/schema.cypher
  docker exec -i nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass < db/seed.cypher
  docker exec -i nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass < db/backfill-claims.cypher
else
  say "Graph already has $COUNT node(s) - leaving it alone"
fi

# --- systemd services --------------------------------------------------------
say "Installing systemd services"
NODE_BIN="$(command -v node)"

cat > /etc/systemd/system/nexus-api.service <<UNIT
[Unit]
Description=Nexus API
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR/nexus
ExecStart=$NODE_BIN --env-file-if-exists=.env src/index.js
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/nexus-bot.service <<UNIT
[Unit]
Description=Nexus Telegram Bot
After=nexus-api.service
Requires=nexus-api.service

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR/nexus
ExecStart=$NODE_BIN --env-file-if-exists=.env src/telegram/bot.js
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now nexus-api
systemctl enable --now nexus-bot

say "Done"
cat <<DONE

nexus-api and nexus-bot are running, and will restart on crash or reboot.

  systemctl status nexus-api nexus-bot
  journalctl -u nexus-bot -f
  journalctl -u nexus-api -f

The API is bound to localhost:3000 only - it is NOT reachable from outside
this machine, only the bot (running on the same host) talks to it. Neo4j
and Redis are loopback-only too. If you ever want the API reachable
remotely, set API_KEY in .env first, then open port 3000 in your firewall
or put a reverse proxy in front of it - don't do this without setting
API_KEY, every route but /api/health is otherwise wide open.

DONE
