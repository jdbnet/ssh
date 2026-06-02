#!/bin/bash

cd frontend && npm run build && cd ..
gunicorn --bind 0.0.0.0:5000 --workers 1 --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker app:app --log-level info