# FROM node:21-alpine3.19
FROM node:21


WORKDIR /usr/src/app
COPY package.json ./
COPY package-lock.json ./
RUN npm install

COPY . .
EXPOSE 3004