# COVID-19 Self-reporting API server User IDs

![GitHub pull request check state](https://img.shields.io/github/status/s/pulls/enigmampc/SafeTrace/52)
![Docker-compose version](https://img.shields.io/badge/Docker--Ccompose-%5E1.21.2-brightgreen)
![node-current (tag)](https://img.shields.io/node/v/nodemon/latest)
![NPM version](https://img.shields.io/badge/NPM-6.14.4-verde)
![Mongoose version](https://img.shields.io/badge/MONGO-%5E5.9.4-green)


## Requirements 

You need these packages installed on your machine:
* [Docker and docker-compose](https://docs.docker.com/compose/install/)
* [NPM](https://www.npmjs.com/get-npm)
* [nodejs](https://nodejs.org/en/)

## Installation 

Clone the project and run these commands. 

```
$ cd <your_project_folder>/backend/app/ 

$ npm install

$ cd ..
    
$ docker-compose up --build
```
 
 The node js project will run on http://localhost:4080/
 
 admin-mongo interface will be displayed on http://localhost:8082/  
 (this is deactivated by default. You need to uncomment lines in the docker-compose.yml to activate it)
 
 Internal Mongo DB connection string
 `mongodb://mongo/safetrace`

 External Mongo DB connection string (Robo3t)
 `mongodb://localhost:10975/safetrace` *In the docker-compose.yml file the port configuration is mapping the port 10975 to 27017 just to avoid expose the normal mongodb port.*
 
 .env file has some configurations
- PORT: port where run nodejs 
- MONGOURI: path to access to mongoDB database (`mongodb://mongo/safetrace`)
- GOOGLE_CLIENT_ID= client id path to register and validate users for Google sign up service. More innformation [here](https://developers.google.com/identity/sign-in/web/backend-auth).

app/config/config.js
  - >secret: 'youSecretWord'  
  - This configuration is used to encrypt the user id. It must be changed for every different app. *This is a temporary solution for the MVP version.* 

# Google Sign In integration

## /user/glogin

This endpoint registers new Google users if it don't exist. And logs in the user. It returns the internal token that you have to use for the next requests (header `x-access-token`)

```
curl --location --request POST 'http://localhost:4080/user/glogin' \
--header 'Content-Type: application/json' \
--data-raw '{
	"token": "eyJhbGciO0eXAiOi...LeLIU9ZMrVoCV2xA"
}'
```
**Returns**

```
{
    "token": "eyJhbGciOiJIUzI1NiIs...yiV2CNK12IVGESQ"
}
```

# JWT User endpoints

## /user/signup

```
curl --location --request POST 'https://localhost:4080/user/signup' \
--header 'Content-Type: application/json' \
--data-raw '{
	"username": "username",
	"email": "name@domain.com",
	"password": "yourpass",
    "agreeToBeNotified": true
}'
```
**Returns**
```
{
    "token": "eyJhbGciOiJIUzI1NiI....bJI7QTsgyM3Qk0"
}
```

## /user/login

```
curl --location --request POST 'http://localhost:4080/user/login' \
--header 'Content-Type: application/json' \
--data-raw '{
	"email": "name@domain.com",
	"password": "yourpass"
}'
```
**Returns**
```
{
    "token": "eyJhbGciOiJIUzI1NiIs....R-sJ9iHNUde0"
}
```

## /user/me

```
curl --location --request GET 'http://localhost:4080/user/me' \
--header 'x-access-token: eyJhbGci....blSXAPm0'

```
**Returns**
```
{
    "agreeToBeNotified": false,
    "userType": 1,
    "createdAt": "2020-04-02T10:16:12.090Z",
    "_id": "5e85bf05420bac7bcfece08f",
    "username": "username",
    "email": "name@domain.com",
    "password": "$2a$10$21w/RANQMJoc2Ge6FpcSSOCpY1S2ae6li5dv5xNeQEzewphkneGcS",
    "idUser": 1,
    "encryptedUserId": "5f6451160f76aac8a02493787dc940a0057746c6401cc49757664ce1032b8450",
    "__v": 0
}
```

`encryptedUserId` returns the encrypted email as user id.

# Report

## POST: /report 

This let to add a result test to the report table.

```
curl --location --request POST 'http://localhost:4080/report' \
--header 'x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNWU4ODhhZDBlZGEwN2U2ZGFlYjY0ODBiIn0sImlhdCI6MTU4NjAxNjA2MiwiZXhwIjoxNTg2MDE5NjYyfQ.hmxFFAz1P80Yq4Q2iA6D8IpCOhI5_7xkfZYWDkQOHK4' \
--header 'Content-Type: application/json' \
--data-raw '{
	"idUser": "'9365df4e9acef8b63b45dc3534491225ac32630abe6991f6bf5a74c9803412fc'",
	"testDate": "03/02/2020",
	"testResult": 0
}'
```
**Returns**

```
{
    "report": {
        "createdAt": "2020-04-04T16:04:00.725Z",
        "_id": "5e88b01316714c664f5ef11e",
        "idUser": 1,
        "testDate": "2020-03-02T03:00:00.000Z",
        "testResult": 0,
        "idReport": 13,
        "__v": 0
    }
}
```

## GET: /report/{idUser} 

Get the list of reported tests


```
curl --location --request GET 'http://localhost:4080/report/9365df4e9acef8b63b45dc3534491225ac32630abe6991f6bf5a74c9803412fc' \
--header 'x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNWU4ODhhZDBlZGEwN2U2ZGFlYjY0ODBiIn0sImlhdCI6MTU4NjI4Njg4MiwiZXhwIjoxNTg2MjkwNDgyfQ.zVNwkDZCXtlxRJnDhonptMxbgpngrB3T7cNIy8vde_I'
```
**Returns**

```
{
    "reports": [
        {
            "createdAt": "2020-04-07T19:24:31.388Z",
            "_id": "5e8cd38dc43d8007408e600d",
            "idUser": "9365df4e9acef8b63b45dc3534491225ac32630abe6991f6bf5a74c9803412fc",
            "testDate": "2020-03-04T03:00:00.000Z",
            "testResult": 1,
            "idReport": 17,
            "__v": 0
        },
        {
            ...
        }
    ]
}
```

## LICENSE

The code in this repository is released under the [MIT License](https://github.com/cmalfesi/SafeTrace/blob/master/LICENSE).
