FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/server.py
COPY index.html /app/index.html
COPY style.css /app/style.css
EXPOSE 7860
USER 1000
CMD ["python", "server.py"]
