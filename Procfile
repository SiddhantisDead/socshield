release: cd backend && python -m app.seed --with-data
web: cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT
