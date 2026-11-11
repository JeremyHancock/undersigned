# Image for the hosted browser demo (examples/webdemo). The library itself
# needs none of this.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY examples/webdemo ./examples/webdemo

RUN useradd --system --no-create-home demo
USER demo

# PUBLIC_URL must be the https address people reach the demo at: the passkey
# is bound to its hostname.
ENV PORT=8080
EXPOSE 8080
CMD ["python", "examples/webdemo/server.py", "--hosted"]
