FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin tresorry
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app/ /app/
RUN chmod 0555 /app/entrypoint.sh
USER tresorry
EXPOSE 8443
ENTRYPOINT ["/app/entrypoint.sh"]
