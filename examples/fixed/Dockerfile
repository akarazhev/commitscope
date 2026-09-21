# Static analysis fixture only. Image/CVE/runtime hardening is outside this example.
FROM python:3.13-slim
WORKDIR /app
COPY app.py /app/app.py
USER 65532:65532
CMD ["python", "/app/app.py"]
