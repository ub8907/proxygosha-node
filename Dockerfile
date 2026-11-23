FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY . .
RUN npm run build && mkdir -p /app/storage

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "dist-server/server.mjs"]
