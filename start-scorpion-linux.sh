#!/bin/bash
# Scorpion Security Platform - Linux Launcher

echo "🦂 Starting Scorpion Security Platform..."

# Check if npm is available
if ! command -v npm &> /dev/null; then
    echo "❌ npm not found. Please run ./install-linux.sh first."
    exit 1
fi

# Start API server in background
echo "Starting API server..."
npm run server &
SERVER_PID=$!

# Wait for server to be ready
sleep 3

# Start Vite dev server
echo "Starting Web UI..."
npm run dev &
VITE_PID=$!

echo ""
echo "✅ Scorpion is running!"
echo "   Web UI: http://localhost:5173"
echo "   API: http://localhost:3001"
echo "   Login: admin / admin"
echo ""
echo "Press Ctrl+C to stop both servers"

# Trap Ctrl+C and kill both processes
trap "echo ''; echo 'Stopping Scorpion...'; kill $SERVER_PID $VITE_PID 2>/dev/null; exit" INT TERM

# Wait for both processes
wait
