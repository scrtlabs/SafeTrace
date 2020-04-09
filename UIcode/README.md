# React File Upload

- This is a React UI to interact with the backend and the Enclave service.
- It is still in development, for now using it client you can report new user data and upload location history.
- For simplicity, we are currently only supporting Google sign-in

## Quick Start

```bash
# Install dependencies
npm install

# Create .env.development file as follows
touch .env.development
```

Obtain a Google client ID following the instructions on [https://developers.google.com/identity/sign-in/web/sign-in](https://developers.google.com/identity/sign-in/web/sign-in) and make sure to include the `localhost:3000` to authorized origins.
Then add this variable to your `.env.development`

```bash
#set google client id i.e. 119469794689-hhq7rpcmd88c7r5gkiom0u2pakfka3cd.apps.googleusercontent.com
echo "REACT_APP_GOOGLE_CLIENT_ID=119469794689-hhq7rpcmd88c7r5gkiom0u2pakfka3cd.apps.googleusercontent.com" >> .env.development
```

Top run the backend API check [https://github.com/cmalfesi/SafeTrace/tree/master/backend](https://github.com/cmalfesi/SafeTrace/tree/master/backend)
Then add the API URL to your `.env.development`

```bash
#set google client id i.e. 119469794689-hhq7rpcmd88c7r5gkiom0u2pakfka3cd.apps.googleusercontent.com
echo "REACT_APP_GOOGLE_CLIENT_ID=119469794689-hhq7rpcmd88c7r5gkiom0u2pakfka3cd.apps.googleusercontent.com" >> .env.development
```

Finally to run the client execute the following commands:

```bash
# Serve on localhost:3000
npm start
```
