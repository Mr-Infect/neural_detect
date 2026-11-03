FROM python:3.12.8-slim
WORKDIR /app
COPY pyproject.toml alembic.ini ./
COPY apps ./apps
COPY ai_engine ./ai_engine
COPY ai_security ./ai_security
COPY core ./core
COPY integrations ./integrations
COPY scripts ./scripts
COPY detection_engine ./detection_engine
COPY detection_rules ./detection_rules
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["uvicorn","apps.api.main:app","--host","0.0.0.0","--port","8000"]


