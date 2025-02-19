FROM python:3.10

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

# Run the Flask app
CMD ["python3", " server.py"]
