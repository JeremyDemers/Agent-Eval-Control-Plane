FROM python:3.12-slim

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends make \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv
COPY pyproject.toml README.md Makefile ./
COPY src ./src
COPY examples ./examples
COPY scripts ./scripts
COPY tests ./tests
RUN uv sync --extra dev
CMD ["make", "demo"]
