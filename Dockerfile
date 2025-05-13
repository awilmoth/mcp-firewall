FROM python:3.9-slim

WORKDIR /app

# Create necessary directories
RUN mkdir -p /app

# Copy only what we need
COPY app/mcp_firewall.py /app/
COPY smithery.yaml /app/

# Make sure the script is executable
RUN chmod +x /app/mcp_firewall.py

# Create required directories
RUN mkdir -p /app/logs /app/data

# Install required packages
RUN pip install fastapi uvicorn pydantic 
# Install the Smithery SDK
RUN pip install git+https://github.com/smithery-ai/sdk.git#subdirectory=python

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV LOG_LEVEL=DEBUG

# Expose port
EXPOSE 6366

# Command to run the server
CMD ["python", "-u", "/app/mcp_firewall.py"]