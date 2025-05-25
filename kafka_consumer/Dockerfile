FROM python:3.11-slim

WORKDIR /app

RUN pip install kafka-python
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN apt-get update
RUN apt update && apt install -y netcat-openbsd

COPY . .
ENTRYPOINT ["python", "-u", "consumer.py"]

