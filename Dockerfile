FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p debug_data keys

ENV AUDIT_SYSTEM_MODE=demo
ENV FLASK_APP=src.api.routes

EXPOSE 5000

CMD ["python", "-m", "flask", "run", "--host", "0.0.0.0", "--port", "5000"]
