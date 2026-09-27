FROM mcr.microsoft.com/playwright/python:v1.63.0-noble
WORKDIR /app
COPY requirements-pilot.txt /app/
RUN pip install --no-cache-dir -r requirements-pilot.txt
COPY src /app/src
COPY schemas /app/schemas
COPY config /app/config
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER pwuser
