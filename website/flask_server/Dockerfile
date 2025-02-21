FROM python:3.9-slim AS builder

WORKDIR /app
COPY requirements.txt .

# Mise à jour du gestionnaire de paquets et installation des dépendances
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl  # Ajout de curl pour télécharger dockerize \
 && rm -rf /var/lib/apt/lists/*

# Installation des dépendances dans un venv
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


FROM python:3.9-slim
WORKDIR /app

# Copier le venv depuis l'image builder
COPY --from=builder /opt/venv /opt/venv

# Copier les fichiers de l'application Flask
COPY . .

# Installer dockerize dans l'image finale
RUN curl -sSL https://github.com/jwilder/dockerize/releases/download/v0.6.1/dockerize-linux-amd64-0.6.1.tar.gz | tar -xzv -C /usr/local/bin

# Définir les variables d'environnement
ENV PATH="/opt/venv/bin:$PATH"
ENV FLASK_APP=server.py
ENV FLASK_ENV=production

# Exposer le port de l'application Flask
EXPOSE 5000

# Commande d'entrée avec dockerize pour attendre que le service soit prêt
ENTRYPOINT ["dockerize", "-wait=tcp://flask_server:5000", "-timeout=60s", "--", "gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "server:app"]
