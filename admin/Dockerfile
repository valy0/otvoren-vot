FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better layer caching
COPY admin/pyproject.toml .
RUN pip install --no-cache-dir "."

# Copy application code
COPY admin/ .

RUN groupadd -r app && useradd -r -g app app

USER app

EXPOSE 8085

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8085"]
