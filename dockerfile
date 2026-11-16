# Use official lightweight Python base image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Copy dependency requirements first to leverage Docker layer caching
COPY app/requirements.txt .

# Install dependencies without caching pip wheels
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY ./app ./app

# Create logs directory inside container
RUN mkdir -p logs

# Expose container application port
EXPOSE 8000

# Ensure Python output is sent straight to terminal (unbuffered)
ENV PYTHONUNBUFFERED=1

# Run FastAPI via Uvicorn on all network interfaces
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
