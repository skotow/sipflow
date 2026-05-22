FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

COPY sipflow ./sipflow
COPY README.md ./README.md

EXPOSE 8080

CMD ["python", "-m", "sipflow.server", "--host", "0.0.0.0", "--port", "8080"]
