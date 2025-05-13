#!/bin/bash
set -e

# Script to run MCP Firewall
echo "Starting MCP Firewall..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python is not installed. Please install Python first."
    exit 1
fi

# Use python3 as the Python command
PYTHON=python3

# Create log and data directories if they don't exist
mkdir -p app/logs app/data

# Check if requirements are installed
if [ ! -f "requirements.txt" ]; then
    echo "Error: requirements.txt not found. Make sure you're in the root directory of the project."
    exit 1
fi

# Check if virtual environment exists, create if it doesn't
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    $PYTHON -m venv venv
fi

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    echo "Error: Could not find activation script for virtual environment."
    exit 1
fi

# Install requirements if needed
pip install -r requirements.txt

# Check for Smithery SDK
if ! pip show smithery-sdk &> /dev/null; then
    echo "Installing Smithery SDK..."
    pip install git+https://github.com/smithery-ai/sdk.git#subdirectory=python
fi

# Check Python version - Smithery requires Python 3.10+
python_version=$($PYTHON --version | awk '{print $2}')
python_major=$(echo $python_version | cut -d'.' -f1)
python_minor=$(echo $python_version | cut -d'.' -f2)

if [ "$python_major" -lt 3 ] || ([ "$python_major" -eq 3 ] && [ "$python_minor" -lt 10 ]); then
    echo "WARNING: Smithery requires Python 3.10 or later. You have Python $python_version."
    echo "The server may start but might not be compatible with Smithery deployment."
    echo "Do you want to continue anyway? (y/n)"
    read answer
    if [ "$answer" != "y" ]; then
        echo "Exiting. Please install Python 3.10+ and try again."
        exit 1
    fi
fi

# Run the server
echo "Starting MCP Firewall server..."
echo "The server will be available at: http://localhost:6366"
echo "Health check: http://localhost:6366/health"
echo "JSON-RPC endpoint: http://localhost:6366/jsonrpc"
echo "Tools endpoint: http://localhost:6366/tools"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

$PYTHON app/mcp_firewall.py

# Add trap to catch errors
trap 'echo "Server exited unexpectedly. Check logs at app/logs/firewall.log"; exit 1' ERR