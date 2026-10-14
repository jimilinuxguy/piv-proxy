FROM python:3.12-alpine
RUN pip install --no-cache-dir cryptography==44.0.3 redis==5.2.1
WORKDIR /app
COPY server.py .
USER 10001
CMD ["python", "server.py"]
