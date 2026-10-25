FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev --ignore-scripts

COPY server.js ./
COPY src ./src
COPY public ./public

RUN mkdir -p /app/data && chown -R node:node /app
USER node

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3456

EXPOSE 3456

CMD ["node", "server.js"]
