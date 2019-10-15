# Looback4-Boilerplate

This is a API REST Boilerplate for most common requeriments in all project (or it try it).
The capabilities that AlexHg/Loopback4-Boilerplate contemplates in this repository are the following:

1. User Authenticate with JWT Passport and password hashing service secured
2. Role Authorization
3. Email client service adaptabled to local register ENDPOINT
4. Connection with MongoDB Atlas
5. Environment variables (.env file)
6. DataFixtures

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
```

## Running & Configuration
Create .env based on .env.example file and add your data
```
cp .env.example .env
```

Run the project
```
npm start
```

## ENDPOINT DOCUMENTATION
Go to http://localhost:3000/explorer in your explorer to see the documentation.
