#!/bin/bash
set -e

# Script to deploy and run MCP Firewall with SQLite in Docker
echo "MCP Firewall Docker Deployment"
echo "=============================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    exit 1
fi

# Default settings
IMAGE_NAME="mcp-firewall"
CONTAINER_NAME="mcp-firewall"
HOST_PORT=6366
DATA_DIR="$HOME/mcp-firewall-data"
LOGS_DIR="$HOME/mcp-firewall-logs"

# Process command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            HOST_PORT="$2"
            shift 2
            ;;
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --logs-dir)
            LOGS_DIR="$2"
            shift 2
            ;;
        --name)
            CONTAINER_NAME="$2"
            shift 2
            ;;
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --help)
            echo "Usage: ./deploy_docker.sh [options]"
            echo ""
            echo "Options:"
            echo "  --port PORT        Port to expose (default: 6366)"
            echo "  --data-dir DIR     Directory for persisting data (default: ~/mcp-firewall-data)"
            echo "  --logs-dir DIR     Directory for logs (default: ~/mcp-firewall-logs)"
            echo "  --name NAME        Container name (default: mcp-firewall)"
            echo "  --build-only       Only build the image, don't run the container"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help to see available options"
            exit 1
            ;;
    esac
done

# Create data and logs directories if they don't exist
mkdir -p "$DATA_DIR" "$LOGS_DIR"

echo "Building Docker image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" .

if [ "$BUILD_ONLY" = true ]; then
    echo "Image built successfully. Exiting as requested."
    exit 0
fi

# Check if container with the same name already exists
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Container '$CONTAINER_NAME' already exists. Stopping and removing..."
    docker stop "$CONTAINER_NAME" || true
    docker rm "$CONTAINER_NAME" || true
fi

echo "Starting container: $CONTAINER_NAME"
echo "- Port mapping: $HOST_PORT:6366"
echo "- Data directory: $DATA_DIR"
echo "- Logs directory: $LOGS_DIR"

docker run -d \
    --name "$CONTAINER_NAME" \
    -p "$HOST_PORT:6366" \
    -v "$DATA_DIR:/data" \
    -v "$LOGS_DIR:/logs" \
    -e "PORT=6366" \
    -e "DB_PATH=/data/firewall.db" \
    --restart unless-stopped \
    "$IMAGE_NAME"

echo "Container started."
echo "MCP Firewall is available at: http://localhost:$HOST_PORT"
echo "Health check: http://localhost:$HOST_PORT/health"
echo "Database info: http://localhost:$HOST_PORT/db/info"
echo ""
echo "To view logs:"
echo "docker logs $CONTAINER_NAME"
echo ""
echo "To stop the container:"
echo "docker stop $CONTAINER_NAME"