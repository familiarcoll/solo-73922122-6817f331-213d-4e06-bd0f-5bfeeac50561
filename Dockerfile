FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 先装依赖，利用镜像层缓存
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 再拷应用代码
COPY app /app/app

RUN mkdir -p /data && \
    adduser --system --uid 1001 appuser && chown -R appuser /data /app
USER appuser

EXPOSE 8000

# 每容器单 worker：水平扩展靠 compose 的两个进程，
# 跨进程并发由 SQLite WAL + IMMEDIATE 事务保证正确
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
