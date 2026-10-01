FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 kenai && useradd --uid 10001 --gid kenai --create-home kenai
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

COPY alembic.ini ./
COPY migrations ./migrations
RUN chown -R kenai:kenai /app

USER kenai
EXPOSE 8000
CMD ["uvicorn", "kenai_vpn_admin.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
