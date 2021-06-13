FROM node:alpine

WORKDIR /usr/src/app

COPY package.json ./

RUN npm install

COPY . .

ENV PORT 4000
ENV NODE_ENV = "production"

EXPOSE ${PORT}

CMD ["npm", "run", "start" ]