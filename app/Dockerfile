FROM python:3.12-alpine
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app/server.py app/oidc.py /app/
USER 10001
CMD ["python", "server.py"]
