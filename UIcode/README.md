# React File Upload

- This is a React UI to interact with the backend and the Enclave service.
- It is still in development, for now using it client you can report new user data and upload location history.
- For simplicity, we are currently only supporting Google sign-in
> This is a full stack React-Express file uploader but could easily be modified to work with any back-end including cloud storage

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
echo "REACT_APP_API_URL=http://localhost:4080" >> .env.development
```

Include the Enclave URL in your `.env.development`
```bash
echo "REACT_APP_ENCLAVE_URL=https://safetrace.enigma.co" >> .env.development
```

Include Google Maps API Key in your `.env.development`, you can find instructions on how to obtain it here [https://developers.google.com/maps/documentation/javascript/get-api-key](https://developers.google.com/maps/documentation/javascript/get-api-key)

```bash
echo "REACT_APP_GOOGLE_MAPS_API_KEY=AaLeiVHdICmJYzM8w8aSyEzo-TainZ3W3Ev2QfQ" >> .env.development
```

Finally to run the client execute the following commands:

```bash
# Serve on localhost:3000
npm start


# Serve on localhost:3000
npm run dev
```
