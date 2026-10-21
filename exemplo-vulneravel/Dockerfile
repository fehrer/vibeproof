FROM node:latest
WORKDIR /app
COPY . .
ENV JWT_SECRET=segredo-super-forte
RUN npm install
CMD ["node", "src/server.js"]
