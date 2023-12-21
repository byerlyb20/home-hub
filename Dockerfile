FROM node:21-alpine3.18
EXPOSE 8000
VOLUME ["/app/db", "/app/secrets", "/app/ipc"]

WORKDIR /app
COPY . /app
COPY Docker.env /app/.env

RUN npm install
ENTRYPOINT ["node", "/app/app.js"]