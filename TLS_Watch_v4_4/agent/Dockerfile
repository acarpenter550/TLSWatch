FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 AGENT_DATA_DIR=/data AGENT_UI_PORT=8899
WORKDIR /app
RUN pip install --no-cache-dir 'Flask>=3.1,<4'
COPY agent.py .
RUN mkdir /data
EXPOSE 8899
CMD ["python", "agent.py"]
