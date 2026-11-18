#!/bin/bash
# VaultGuard — Khởi chạy nhanh trên macOS (click đúp file này trong Finder)
cd "$(dirname "$0")" || exit 1

if ! command -v npm >/dev/null 2>&1; then
  echo "❌ Chưa cài Node.js. Tải tại https://nodejs.org (bản LTS) rồi chạy lại."
  read -r -p "Nhấn Enter để đóng..."
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "📦 Đang cài đặt dependencies lần đầu..."
  npm install || {
    echo "❌ npm install thất bại."
    read -r -p "Nhấn Enter để đóng..."
    exit 1
  }
fi

echo "🛡️ Đang mở VaultGuard..."
npm start
