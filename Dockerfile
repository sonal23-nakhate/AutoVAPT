FROM python:3.10-slim

WORKDIR /app

# Install system network diagnostics
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies clearly
RUN pip install --no-cache-dir fastapi uvicorn psycopg2-binary streamlit requests pandas apscheduler

COPY . /app

EXPOSE 80
EXPOSE 8501