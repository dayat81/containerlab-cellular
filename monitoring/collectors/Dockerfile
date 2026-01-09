FROM python:3.11-slim

WORKDIR /app

# Install docker CLI for exec commands
RUN apt-get update && apt-get install -y \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY metrics_collector.py /app/

EXPOSE 9200

CMD ["python", "-u", "metrics_collector.py"]
