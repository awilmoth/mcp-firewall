FROM python:3.11-slim

WORKDIR /app

# Copy the entire project
COPY . .

# Create required directories
RUN mkdir -p /app/logs /app/data

# Install system dependencies
RUN apt-get update && apt-get install -y git && apt-get clean

# Install Python dependencies
RUN pip install fastapi uvicorn pydantic mcp
# Install the Smithery SDK
RUN pip install git+https://github.com/smithery-ai/sdk.git#subdirectory=python

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV LOG_LEVEL=DEBUG
ENV PORT=6366

# Expose port
EXPOSE 6366
EXPOSE 80

# Command to run the server
CMD ["python", "-u", "app/mcp_firewall.py"]