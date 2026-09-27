FROM mcr.microsoft.com/playwright/python:v1.63.0-noble
WORKDIR /app
COPY requirements-pilot.txt /app/
RUN pip install --no-cache-dir -r requirements-pilot.txt
COPY src /app/src
COPY schemas /app/schemas
COPY config/observation_pilot_v1.json /app/config/observation_pilot_v1.json
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER pwuser
