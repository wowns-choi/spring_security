# Spring Security JWT Demo

This project is a Spring Boot application designed to demonstrate the implementation of authentication and authorization using Spring Security and JSON Web Tokens (JWT).

## Project Overview

*   **Type:** Spring Boot Application
*   **Language:** Java 17
*   **Core Framework:** Spring Boot 3.5.6
*   **Security:** Spring Security (Stateless JWT architecture)
*   **Database:** H2 In-memory database
*   **Token Library:** JJWT 0.13.0

## Architecture & Security

The application uses a **Stateless** security model. Sessions are not created; instead, a JWT is issued upon login and must be presented in the `Authorization` header (`Bearer <token>`) for subsequent requests.

### Key Components

*   **`SecurityConfig.java`**:
    *   Configures the `SecurityFilterChain`.
    *   Disables CSRF and Sessions (Stateless).
    *   Configures public endpoints (`/signin`, `/api/public/**`, `/h2-console/**`).
    *   Adds `AuthTokenFilter` before the standard `UsernamePasswordAuthenticationFilter`.
    *   Uses `JdbcUserDetailsManager` to store user data in the H2 database.
*   **`JwtUtils.java`**:
    *   Handles JWT creation (signing with HMAC SHA), parsing, and validation.
    *   Secret key is configured via `spring.app.jwtSecret`.
*   **`AuthTokenFilter.java`**:
    *   A `OncePerRequestFilter` that intercepts HTTP requests.
    *   Extracts the JWT from the header, validates it, and sets the `Authentication` in the `SecurityContext`.
*   **`GreetingController.java`**:
    *   Handles authentication at `/signin`.
    *   Provides protected endpoints (`/user`, `/admin`, `/profile`) to test authorization.
*   **`UserController.java`**:
    *   Provides a public endpoint (`/api/public/users`) to register new users.

### Default Users
The application initializes the following users on startup (via `CommandLineRunner` in `SecurityConfig`):
*   **Username:** `user1` / **Password:** `password1` (Role: USER)
*   **Username:** `admin` / **Password:** `adminPass` (Role: ADMIN)

## Building and Running

This project uses Maven Wrapper.

### 1. Run the Application
```bash
./mvnw spring-boot:run
```

### 2. Build the JAR
```bash
./mvnw clean package
```

### 3. Run Tests
```bash
./mvnw test
```

## Configuration

Configuration is managed in `src/main/resources/application.properties`.

*   **Server Port:** Default (8080)
*   **Database:** H2 In-memory (`jdbc:h2:mem:test`)
*   **JWT Settings:**
    *   `spring.app.jwtSecret`: The secret key for signing tokens.
    *   `spring.app.jwtExpirationMs`: Token expiration time (default: 3600000ms / 1 hour).

## API Usage

1.  **Register (Optional):**
    *   **POST** `/api/public/users`
    *   **Params:** `username`, `password`, `role`
2.  **Login:**
    *   **POST** `/signin`
    *   **Body:** `{"username": "user1", "password": "password1"}`
    *   **Response:** JSON containing the JWT token.
3.  **Access Protected Resources:**
    *   Include header: `Authorization: Bearer <your_jwt_token>`
    *   **GET** `/hello` (Requires Auth)
    *   **GET** `/user` (Requires Role USER)
    *   **GET** `/admin` (Requires Role ADMIN)
    *   **GET** `/profile` (Returns user details)