# Étape 1 : Build avec Node.js
FROM node:18-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json ./ 
RUN npm install --frozen-lockfile

COPY . . 

# Injection de la variable d’environnement au moment du build
ARG VITE_API_BASE_URL
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN npm run build

# Étape 2 : Servir avec NGINX
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
