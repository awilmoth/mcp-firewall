FROM python:3.11-alpine

WORKDIR /app

# Install dependencies
RUN apk add --no-cache curl

# Create app directories
RUN mkdir -p /app/app/logs /app/app/data

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/mcp_firewall.py ./app/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Make script executable
RUN chmod +x app/mcp_firewall.py

# Expose port
EXPOSE 6366

# Run the application
CMD ["python", "-u", "app/mcp_firewall.py"]