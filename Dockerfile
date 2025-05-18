FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p web_templates web_static/css web_static/js

# Expose ports for API, Web UI
EXPOSE 8000 8080

# Create a non-root user to run the app
RUN useradd -m appuser
RUN chown -R appuser:appuser /app
USER appuser

# Command can be overridden by docker-compose
CMD ["python", "fast_app.py"] 