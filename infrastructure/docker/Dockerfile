FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# BUILD_ENV=prod        installs requirements.txt only -- no transformer (~base image, default)
# BUILD_ENV=transformer installs requirements-transformer.txt -- includes torch/transformers (~1.5GB extra)
# BUILD_ENV=dev         installs requirements-dev.txt -- includes pytest
ARG BUILD_ENV=prod
COPY requirements*.txt ./
RUN if [ "$BUILD_ENV" = "dev" ]; then \
        pip install --no-cache-dir -r requirements-dev.txt; \
    elif [ "$BUILD_ENV" = "transformer" ]; then \
        pip install --no-cache-dir -r requirements-transformer.txt \
            --extra-index-url https://download.pytorch.org/whl/cpu; \
    else \
        pip install --no-cache-dir -r requirements.txt; \
    fi

# Copy application
COPY . .

# Train demo ML model (offline, uses curated fallback dataset only)
RUN PYTHONPATH=/app python scripts/train_ml_model.py --offline

# Create non-root user
RUN adduser --disabled-password --gecos "" wrapsec
RUN chown -R wrapsec:wrapsec /app
USER wrapsec

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]