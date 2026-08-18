FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
# curl is required by the docker-compose healthcheck
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user up front so COPY --chown works without a duplicate layer
RUN adduser --disabled-password --gecos "" wrapsec

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

# Copy application with wrapsec ownership in a single layer
COPY --chown=wrapsec:wrapsec . .

# Install Python SDK so sdk/python/tests are importable in-container
RUN pip install --no-cache-dir -e sdk/python/

USER wrapsec

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]