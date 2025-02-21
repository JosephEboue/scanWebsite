# Étape 1 : Build avec Node.js (Optimisé)
FROM node:18-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --frozen-lockfile

COPY . . 
RUN npm run build

# Étape 2 : Servir avec NGINX
FROM nginx:alpine

# Installer dockerize dans l'image finale
RUN apk add --no-cache curl && \
    curl -sSL https://github.com/jwilder/dockerize/releases/download/v0.6.1/dockerize-linux-amd64-0.6.1.tar.gz | tar -xzv -C /usr/local/bin

# Copier les fichiers build du frontend
COPY --from=builder /app/dist /usr/share/nginx/html

# Exposer le port 80 pour le service NGINX
EXPOSE 80

# Attendre que le service flask_server soit prêt avant de démarrer nginx
ENTRYPOINT ["dockerize", "-wait=tcp://flask_server:5000", "-timeout=60s", "--", "nginx", "-g", "daemon off;"]
