#define the latest nodejs image  to build from
FROM node:latest
RUN mkdir -p /usr/src/apiServerUsers

#create a working directory
WORKDIR /usr/src/apiServerUsers
RUN npm install -g nodemon --save

#copy package.json file under the working directory 
COPY package.json /usr/src/apiServerUsers/
RUN npm install

#copy all your files under the working directory
COPY . /usr/src/apiServerUsers/

EXPOSE 4080
#start nodejs server 
CMD nodemon server.js