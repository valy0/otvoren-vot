FROM python:3.12-slim

WORKDIR /app

# Copy application code and install
COPY admin/ .
RUN pip install --no-cache-dir hatchling && pip install --no-cache-dir "."

RUN groupadd -r app && useradd -r -g app app

USER app

EXPOSE 8085

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8085"]
