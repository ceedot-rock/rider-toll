# Tollkeeper deploy image. Stdlib-only service: no pip install step.
FROM python:3.12-slim
WORKDIR /srv
COPY tollkeeper/ ./tollkeeper/
ENV PORT=8080
ENV TOLLKEEPER_DB=/data/tollkeeper.db
EXPOSE 8080
CMD ["python3", "-m", "tollkeeper.server"]
