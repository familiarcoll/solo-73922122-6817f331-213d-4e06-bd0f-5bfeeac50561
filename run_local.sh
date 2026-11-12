#!/usr/bin/env bash
# 无 Docker 时的本地双进程演示启动脚本（Linux/macOS）。
# 与 docker-compose.yml 等价：两个 uvicorn 进程共享同一个 SQLite 数据目录。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$ROOT/data"
mkdir -p "$DATA_DIR"
export APP_DB_PATH="$DATA_DIR/app.db"
export MAIL_DB_PATH="$DATA_DIR/mail.db"
export HASH_DELAY_MS="${HASH_DELAY_MS:-4000}"
export RESET_TTL_SECONDS="${RESET_TTL_SECONDS:-600}"

PY="${PYTHON:-python3}"
PIDS=()

cleanup() {
  echo
  echo "停止演示进程..."
  kill "${PIDS[@]}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "启动 Web 进程 1: http://127.0.0.1:8001"
"$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --workers 1 &
PIDS+=($!)

echo "启动 Web 进程 2: http://127.0.0.1:8002"
"$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8002 --workers 1 &
PIDS+=($!)

echo
echo "入口: http://127.0.0.1:8001/   (进程2: http://127.0.0.1:8002/)"
echo "预置账号: alice / Wonderland-1 ,  bob / Secret-2"
echo "按 Ctrl+C 停止。数据保存在 $DATA_DIR，重启不丢失。"
wait
