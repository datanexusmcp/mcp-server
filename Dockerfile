FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x start.sh

ENV PYTHONUNBUFFERED=1

# start.sh runs dashboard (8101) + MCP server (8000)
CMD ["./start.sh"]
