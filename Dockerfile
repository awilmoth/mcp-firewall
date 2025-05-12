FROM python:3.9-slim

WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/app

# Copy only what we need
COPY app/basic_server.py /app/app/
COPY smithery.yaml /app/

# Make sure the script is executable
RUN chmod +x /app/app/basic_server.py

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV LOG_LEVEL=DEBUG

# Expose port
EXPOSE 6366

# Command to run the server
CMD ["python", "-u", "/app/app/basic_server.py"]