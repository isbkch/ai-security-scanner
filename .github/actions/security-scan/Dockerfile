FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the scanner code
COPY ai_security_scanner/ ai_security_scanner/
COPY pyproject.toml .
COPY setup.py* ./

# Install the scanner
RUN pip install -e .

# Create entrypoint script
COPY .github/actions/security-scan/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]