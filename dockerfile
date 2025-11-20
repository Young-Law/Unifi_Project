# Use official Python base image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY app/requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY ./app ./app
COPY ./logs ./logs

# Expose port (FastAPI default)
EXPOSE 8000

# Set environment variable for Uvicorn
ENV PYTHONUNBUFFERED=1

# Command to run FastAPI with reload disabled (use reload only for dev)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
