#!/bin/bash
set -e

# Script to run MCP Firewall
echo "Starting MCP Firewall..."

# Check if Python is installed
if ! command -v python &> /dev/null; then
    echo "Error: Python is not installed. Please install Python first."
    exit 1
fi

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
    python -m venv venv
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

# Run the server
echo "Starting MCP Firewall server..."
python app/mcp_firewall.py