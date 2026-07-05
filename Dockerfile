FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps for cryptography/argon2 wheels are prebuilt; keep image slim.
# Copy sources before install: setuptools packages=["app"] needs app/ present.
COPY pyproject.toml ./
COPY app ./app
RUN pip install --upgrade pip && pip install .

EXPOSE 8000

# Run as non-root
RUN useradd -m vcm && chown -R vcm /app
USER vcm

# Trust proxy headers only from the container network / configured proxies (see env).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
