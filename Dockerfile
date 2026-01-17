FROM python:3.9-slim

# Install Tesseract and languages
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-hin \
    tesseract-ocr-tam \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

# Start the server
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000", "--workers", "1", "--timeout", "120"]