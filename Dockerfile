FROM node:22-bookworm-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
COPY --from=frontend /static/dist /app/static/dist
ENV GEVENT_MONKEY_PATCH=1
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--worker-class", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "app:app", "--log-level", "warning"]