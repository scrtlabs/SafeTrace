# React File Upload

> This is a full stack React-Express file uploader but could easily be modified to work with any back-end including cloud storage

## Quick Start

```bash
# Install dependencies server/client
npm install
cd client
npm install

# Create .env.development file as follows
touch .env.development

# set API url i.e. http://localhost:4080
echo "REACT_APP_API_URL=http://localhost:4080" >> .env.development

#set google client id i.e. 119469794689-hhq7rpcmd88c7r5gkiom0u2pakfka3cd.apps.googleusercontent.com
echo "REACT_APP_GOOGLE_CLIENT_ID=119469794689-hhq7rpcmd88c7r5gkiom0u2pakfka3cd.apps.googleusercontent.com" >> .env.development

# Serve on localhost:3000
cd client
npm start
```
