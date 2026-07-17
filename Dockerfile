FROM python:3.12-slim AS runtime
WORKDIR /opt/square-protect
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir .
ENV SPI_DATA_DIR=/data \
    SPI_HOST=0.0.0.0 \
    SPI_PORT=8000
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=60s --timeout=5s CMD ["python", "-c", "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"SPI_PORT\",\"8000\")}/api/status')"]
CMD ["python", "-m", "app"]
