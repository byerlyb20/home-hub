FROM node:lts
EXPOSE 8000
VOLUME ["/app/db", "/app/secrets", "/app/ipc"]

WORKDIR /app

COPY package.json package-lock.json /app
RUN npm install

COPY . /app
COPY Docker.env /app/.env

ENTRYPOINT ["node", "/app/app.js"]