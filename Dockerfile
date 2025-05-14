FROM python:3.11-slim

WORKDIR /app

# Create required directories
RUN mkdir -p /app/logs /app/data

# Install system dependencies
RUN apt-get update && apt-get install -y git sqlite3 && apt-get clean

# Install Python dependencies directly
RUN pip install --no-cache-dir fastapi uvicorn pydantic requests python-dotenv
RUN pip install --no-cache-dir git+https://github.com/smithery-ai/sdk.git#subdirectory=python

# Copy the rest of the application
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV LOG_LEVEL=INFO
ENV PORT=6366
ENV DB_PATH=/data/firewall.db

# Create volume mount points
VOLUME ["/data", "/logs"]

# Expose port
EXPOSE 6366
EXPOSE 80

# Entry point script to ensure data directories are properly set up
RUN echo '#!/bin/bash\n\
mkdir -p /data /logs\n\
ln -sf /logs /app/app/logs\n\
ln -sf /data /app/app/data\n\
python -u /app/app/mcp_firewall.py\n\
' > /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

# Command to run the server
ENTRYPOINT ["/app/docker-entrypoint.sh"]