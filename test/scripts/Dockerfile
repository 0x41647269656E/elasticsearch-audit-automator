FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY load_data.py ./
COPY query_worker.py ./
COPY dummy_data.json ./dummy_data.json
COPY audit_policy_7.json    /app/audit_policy_7.json
COPY audit_policy_8.json    /app/audit_policy_8.json

CMD ["python", "load_data.py"]
