# Looback4-Boilerplate

This is a API REST Boilerplate for most common requeriments in all project (or it try it).
The capabilities that AlexHg/Loopback4-Boilerplate contemplates in this repository are the following:

1. User Authenticate with JWT Passport and password hashing service secured
2. Role Authorization
3. Email client service adaptabled to local register ENDPOINT
4. Connection with MongoDB Atlas
5. Environment variables (.env file)
6. DataFixtures

Extras
1. (Dependencia de nodemon) Code watcher

## Instalation
Cloning the repositorie
```
git clone https://github.com/AlexHg/Loopback4-Boilerplate.git <YOUR_PROJECT_NAME>
cd <YOUR_PROJECT_NAME>
rm -rf .git
git init
git remote add origin <YOUR_OWN_REPOSITORY_URL>
```

Dependencies instalation
```
npm i
npm install -g nodemon
```

## Running & Configuration
Create .env based on .env.example file and add your data
```
cp .env.example .env
```

Run the project
```
npm run start:watch
```


## Create Controllers

## Create Models

## Create Repositories

## Create Datasources

## Create Services


## Add Environment Variables
Insert a new line in the .env file following the file style, when thats complete, you can add the env.var in your code like
```
process.env.ENVIRONMENT_VAR
```



## ENDPOINT DOCUMENTATION
Go to http://localhost:3000/explorer in your explorer to see the documentation.
