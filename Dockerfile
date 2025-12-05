FROM python:3.11-slim

WORKDIR /code

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install alembic & pymysql if not in requirements
RUN pip install alembic pymysql

# Copy app
COPY . .

# Ensure static folder exists
RUN mkdir -p static/images

# Expose port (will be set via env FASTAPI_PORT)
EXPOSE 8001

CMD ["uvicorn", "LM-APIServer:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "4", "--log-level", "info"]
