#!/bin/bash
# Wait for the container to fully initialize
sleep 2

# Install dependencies if not already installed
if [ ! -f "/app/requirements_installed" ]; then
    pip install -r requirements.txt
    touch /app/requirements_installed
fi

# Run the Flask application
exec flask run --host=0.0.0.0 --port=5000