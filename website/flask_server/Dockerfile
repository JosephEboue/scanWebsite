FROM python:3.9-slim AS builder

WORKDIR /app
COPY requirements.txt .

# Mise à jour de gestionnaire de paquets et installation les dépendances
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*
# Installation des dépendances dans un venv
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


FROM python:3.9-slim
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY . .
# Définir les variables d'environnement
ENV PATH="/opt/venv/bin:$PATH"
ENV FLASK_APP=server.py
ENV FLASK_ENV=production

# Exposer le port de l'application Flask
EXPOSE 5000
# Lancer le serveur Flask avec Gunicorn 
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "server:app"]
