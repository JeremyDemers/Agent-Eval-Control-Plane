FROM python:3.12-slim AS runtime

WORKDIR /app
RUN pip install --no-cache-dir uv
COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples
RUN uv sync --no-dev \
    && useradd --create-home --uid 10001 aecontrol \
    && chown -R aecontrol:aecontrol /app
USER 10001
EXPOSE 8000
CMD ["uv", "run", "aecontrol", "serve", "--host", "0.0.0.0"]

FROM runtime AS demo

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends make \
    && rm -rf /var/lib/apt/lists/*
COPY Makefile ./
COPY scripts ./scripts
COPY tests ./tests
RUN uv sync --extra dev && chown -R aecontrol:aecontrol /app
USER 10001
CMD ["make", "demo"]
