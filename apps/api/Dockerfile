FROM python:3.12.8-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml alembic.ini requirements.txt requirements.lock ./
COPY apps ./apps
COPY ai_engine ./ai_engine
COPY ai_security ./ai_security
COPY core ./core
COPY integrations ./integrations
COPY scripts ./scripts
COPY detection_engine ./detection_engine
COPY ndctl ./ndctl
COPY detection_rules ./detection_rules
RUN pip install --no-cache-dir -r requirements.lock && pip install --no-cache-dir --no-deps . && addgroup --system app && adduser --system --ingroup app app && chown -R app:app /app
USER app
EXPOSE 8000
CMD ["sh","-c","alembic upgrade head && exec uvicorn apps.api.main:app --host 0.0.0.0 --port 8000"]

FROM runtime AS test
USER root
RUN pip install --no-cache-dir ".[dev]"
COPY --chown=app:app tests ./tests
USER app
CMD ["pytest", "-q"]

FROM runtime AS production
