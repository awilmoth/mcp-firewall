#!/bin/bash
set -e

# Script to deploy MCP Firewall to Smithery
echo "Deploying MCP Firewall to Smithery..."

# Check if smithery CLI is installed
if ! command -v smithery &> /dev/null; then
    echo "Error: Smithery CLI is not installed. Please install it first."
    exit 1
fi

# Check if smithery.yaml exists
if [ ! -f "smithery.yaml" ]; then
    echo "Error: smithery.yaml not found. Make sure you're in the root directory of the project."
    exit 1
fi

# Build and push the Docker image to Smithery
echo "Building and pushing Docker image to Smithery..."
smithery build .

# Deploy the image to Smithery
echo "Deploying to Smithery..."
smithery deploy

echo "MCP Firewall has been deployed to Smithery!"
echo "Access it at: https://your-smithery-url.example.com/mcp-firewall"