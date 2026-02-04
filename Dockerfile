# Use a lightweight Python version
FROM python:3.9-slim

# 1. Install System Dependencies (Tesseract OCR & ZBar for QR Codes)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# 2. Set up the working directory
WORKDIR /app

# 3. Copy your project files into the container
COPY . .

# 4. Install Python libraries from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 5. Command to run the app using Gunicorn (Production Server)
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000"]