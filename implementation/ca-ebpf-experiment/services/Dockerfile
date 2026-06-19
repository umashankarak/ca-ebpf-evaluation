FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy service file (overridden per service at build time via --build-arg)
ARG SERVICE_FILE
COPY ${SERVICE_FILE} app.py

# Non-root user for security
RUN useradd -r -u 1000 -g root svcuser
USER 1000

EXPOSE 5000 5001 5002 5003

CMD ["python", "app.py"]
