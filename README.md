# Mini Auth

A robust authentication service built with NestJS that provides dual authentication methods - JWT tokens for users and API keys for services. This project demonstrates best practices for secure authentication, password management, and API key generation.

## Features

- **User Authentication**: Secure signup and login with JWT tokens
- **API Key Management**: Generate and manage API keys for service-to-service authentication
- **Dual Authentication Middleware**: Support for both JWT and API key authentication
- **Password Security**: Strong password validation with bcrypt hashing
- **API Documentation**: Auto-generated Swagger documentation
- **Database Integration**: PostgreSQL with Prisma ORM
- **Rate Limiting**: Built-in throttling to prevent abuse
- **Security Best Practices**: Protection against timing attacks, user enumeration, and common vulnerabilities

## Technology Stack

- **Framework**: NestJS
- **Language**: TypeScript
- **Database**: PostgreSQL with Prisma ORM
- **Authentication**: JWT with Passport
- **Password Hashing**: bcrypt
- **API Documentation**: Swagger/OpenAPI
- **Validation**: class-validator and class-transformer
- **Rate Limiting**: @nestjs/throttler

## Getting Started

### Prerequisites

- Node.js (v18 or higher)
- PostgreSQL database
- npm or yarn

### Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd mini-auth
```

2. Install dependencies:

```bash
npm install
```

3. Set up environment variables:

```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Set up the database:

```bash
# Generate Prisma client
npx prisma generate

# Run database migrations
npx prisma migrate dev
```

5. Start the application:

```bash
# Development mode
npm run start:dev

# Production mode
npm run build
npm run start:prod
```

The application will be available at `http://localhost:3000`

### API Documentation

Once the application is running, you can access the interactive API documentation at:
`http://localhost:3000/api/docs`

## API Endpoints

### Authentication

#### `POST /auth/signup`

Register a new user account.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "name": "John Doe"
}
```

#### `POST /auth/login`

Authenticate with email and password.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### API Keys

#### `POST /keys/create`

Create a new API key (requires JWT authentication).

**Headers:**

```
Authorization: Bearer <your-jwt-token>
```

**Request Body:**

```json
{
  "name": "My Service",
  "expirationDays": 90
}
```

**Response:**

```json
{
  "message": "SAVE THIS KEY — shown only once!",
  "apiKey": "sk_550e8400-e29b-41d4-a716-446655440000_abc123def456...",
  "details": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "My Service",
    "expiresAt": "2024-03-01T12:00:00.000Z",
    "preview": "sk_550e...a1b2"
  }
}
```

#### `DELETE /keys/:id`

Revoke an API key (requires JWT authentication).

**Headers:**

```
Authorization: Bearer <your-jwt-token>
```

## Authentication Methods

### JWT Authentication

For user-based authentication, include the JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

### API Key Authentication

For service-to-service authentication, include the API key in the X-API-Key header:

```
X-API-Key: sk_550e8400-e29b-41d4-a716-446655440000_abc123def456...
```

## Security Features

### Password Security

- Minimum 8 characters with complexity requirements
- bcrypt hashing with 12 rounds
- Protection against timing attacks
- Common password detection

### API Key Security

- Cryptographically secure random key generation
- HMAC-SHA256 signature verification
- Optional expiration dates
- Secure key format: `sk_{id}_{random}_{signature}`

### Authentication Security

- Dual authentication support (JWT + API Key)
- Protection against user enumeration
- Secure token handling
- Rate limiting to prevent brute force attacks

## Environment Variables

Create a `.env` file with the following variables:

```env
# Database
DATABASE_URL="postgresql://username:password@localhost:5432/mini_auth"
DIRECT_URL="postgresql://username:password@localhost:5432/mini_auth"

# JWT Secrets
JWT_SECRET="your-super-secret-jwt-key"
JWT_REFRESH_SECRET="your-super-secret-refresh-key"

# API Key Secret
API_KEY_SECRET="your-api-key-secret-for-signing"

# Application
PORT=3000
NODE_ENV=development
```

## Database Schema

The application uses two main entities:

### User

- `id`: UUID primary key
- `email`: Unique email address
- `password`: Bcrypt hashed password
- `name`: Optional display name
- `refreshToken`: Hashed refresh token
- `lastLoginAt`: Last login timestamp
- `isActive`: Account status
- `createdAt/updatedAt`: Timestamps

### ApiKey

- `id`: UUID primary key
- `key`: Unique API key
- `name`: Descriptive name
- `expiresAt`: Optional expiration date
- `isActive`: Key status
- `userId`: Foreign key to User
- `createdAt`: Creation timestamp

## Development

### Running Tests

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
```

### Code Quality

```bash
# Linting
npm run lint

# Formatting
npm run format
```

### Database Management

```bash
# Create new migration
npx prisma migrate dev --name <migration-name>

# Reset database
npx prisma migrate reset

# View database
npx prisma studio
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the UNLICENSED license.

## Support

For questions and support, please open an issue in the repository.
