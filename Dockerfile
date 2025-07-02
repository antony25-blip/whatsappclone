# Use official slim Python image
FROM python:3.11-slim

# Install system dependencies and configure UTF-8 locale
RUN apt-get update && apt-get install -y \
    locales \
    build-essential \
    python3-dev \
    gcc \
    && echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen \
    && locale-gen en_US.UTF-8 \
    && update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables for locale
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Set working directory in container
WORKDIR /app

# Copy local project files into the container
COPY . .

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Expose the port your Flask app runs on (Render uses 10000 internally)
EXPOSE 10000

# Run the app using Gunicorn with 3 workers (adjust if needed)
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "app:app"]
