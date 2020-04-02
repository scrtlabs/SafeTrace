## COVID-19 Self-reporting API server User IDs


## Requirements 

You should have docker and docker-compose installed on your machine 

## Installation 

* clone the project from the repo 
* cd -> project directory and run your project using the following command 
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
 



# JWT User endpoints

## /user/signup

```
curl --location --request POST 'https://localhost:4080/user/signup' \
--header 'Content-Type: application/json' \
--data-raw '{
	"username": "username",
	"email": "name@domain.com",
	"password": "yourpass"
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
    "createdAt": "2020-04-02T10:16:12.090Z",
    "_id": "5e85bf05420bac7bcfece08f",
    "username": "username",
    "email": "name@domain.com",
    "password": "$2a$10$21w/RANQMJoc2Ge6FpcSSOCpY1S2ae6li5dv5xNeQEzewphkneGcS",
    "idUser": 1,
    "__v": 0
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