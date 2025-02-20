# Étape 1 : Utiliser une image légère de Python
FROM python:3.9-slim AS builder

WORKDIR /app

COPY requirements.txt .

# Mettre à jour le gestionnaire de paquets et installer les dépendances
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Installer les dépendances dans un venv
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Étape 2 : Construire l'image finale
FROM python:3.9-slim

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY . .

# Définir les variables d'environnement
ENV PATH="/opt/venv/bin:$PATH"
ENV FLASK_APP=server.py
#ENV FLASK_ENV=production

# Exposer le port de l'application Flask
EXPOSE 5000

# Lancer le serveur Flask avec Gunicorn 
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "server:app"]
