## COVID-19 Self-reporting API server User IDs


## Requirements 

You should have docker and docker-compose installed on your machine 

## Installation 

* clone the project from the repo 
* cd <your_project_folder>/backend/
* Run this command
    ```
    $ docker-compose up --build
    ```
 
 The node js project will run on http://localhost:4080/
 
 * admin-mongo interface will be displayed on http://localhost:8082/  
 (this is deactivated by default. You need to uncomment lines in the docker-compose.yml to activate it)
 
 * Internal Mongo DB connection string
 `mongodb://mongo/safetrace`

 * External Mongo DB connection string (Robo3t)
 `mongodb://localhost:10975/safetrace`
 
 * .env file has some configurations
    - PORT: port where run nodejs 
    - MONGOURI: path to access to mongoDB database (`mongodb://mongo/safetrace`)
    - GOOGLE_CLIENT_ID= client id path to register and validate users for Google sign up service

# Google Sign In integration

## /user/glogin

This endpoint register new google users if it doesn't exist. And login in the user. It returns the internal token that you have to use for the next requests (header `x-access-token`)

```
curl --location --request POST 'http://localhost:4080/user/glogin' \
--header 'Content-Type: application/json' \
--data-raw '{
	"token": "eyJhbGciO0eXAiOi...LeLIU9ZMrVoCV2xA"
}'
```
**Retuns**

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
--header 'token: eyJhbGci....blSXAPm0'

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

## /report 

This let to add a result test report. Use auth-user-type to inform the type of user:
- 0 = internal registered user 
- 1 = google user


```
curl --location --request POST 'http://localhost:4080/report' \
--header 'x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNWU4ODhhZDBlZGEwN2U2ZGFlYjY0ODBiIn0sImlhdCI6MTU4NjAxNjA2MiwiZXhwIjoxNTg2MDE5NjYyfQ.hmxFFAz1P80Yq4Q2iA6D8IpCOhI5_7xkfZYWDkQOHK4' \
--header 'Content-Type: application/json' \
--data-raw '{
	"idUser": "1",
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

# Migrations
source: https://www.npmjs.com/package/migrate-mongo

# Mongo Commands
## Mongo CSV import example
docker-compose exec mongo mongoimport --host mongo --db myappdb --collection ciudads --type csv --fields idProvincia,idCiudad,ciudad,ciudadCorta --file /data/db/CodCiudad.csv
 
## Mongo Export/Import
Export: ``mongodump --db myappdb``

Import: ``mongorestore -d myappdb /dump/myappdb``

LICENSE
The code in this repository is released under the [MIT License](https://github.com/cmalfesi/SafeTrace/blob/master/LICENSE).