FROM python:3.9-slim

WORKDIR /app

# Create app directories
RUN mkdir -p /app/app/logs /app/app/data

# Copy application code - using the basic server for simplicity
COPY app/basic_server.py ./app/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Make script executable
RUN chmod +x app/mcp_firewall.py

# Expose port
EXPOSE 6366

# Run the application
CMD ["python", "-u", "app/basic_server.py"]