#!/bin/bash

if [ ! -d "venv" ]; then
    echo "Creating virtual environment in 'venv'..."
    python3 -m venv venv
    source venv/bin/activate
    if [ -f "requirements.txt" ]; then
        echo "Installing requirements..."
        pip install -r requirements.txt
    fi
else
    source venv/bin/activate
fi

cd frontend && npm run build && cd ..
exec gunicorn --bind 0.0.0.0:5000 --workers 1 --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker app:app --log-level info