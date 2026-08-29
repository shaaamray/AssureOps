FROM python:3.12-slim

# Non root by default: this tool needs no privileges.
RUN useradd --create-home --uid 10001 assureops

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY config ./config

USER assureops
ENTRYPOINT ["assureops"]
CMD ["--help"]
