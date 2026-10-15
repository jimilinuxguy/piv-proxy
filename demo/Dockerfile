FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir cryptography==44.0.3
COPY server.py .
USER 10001
CMD ["python", "server.py"]
