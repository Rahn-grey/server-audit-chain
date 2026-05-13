FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p debug_data keys

ENV AUDIT_SYSTEM_MODE=demo
ENV FLASK_APP=src.api.routes
ENV FLASK_ENV=development

EXPOSE 5000

CMD ["python", "-m", "flask", "run", "--host", "0.0.0.0", "--port", "5000"]
