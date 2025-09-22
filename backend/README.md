# ChatApp Auth Backend

This backend supports **register, login, logout** with persistence.

## Features
- Register new users (saved in db.json)
- Login with username + password (returns JWT token)
- Logout (blacklists token)
- Protected route example: `/api/profile`

## Setup
```bash
npm install
npm start
```

## API Endpoints
- POST `/api/register` `{ "username": "alice", "password": "1234" }`
- POST `/api/login` `{ "username": "alice", "password": "1234" }`
- POST `/api/logout` (with Authorization: Bearer <token>)
- GET `/api/profile` (protected, needs token)
```

