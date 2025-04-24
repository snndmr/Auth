# Spring Boot Authentication & Authorization Demo Project

## 1. Project Overview

This project is a hands-on demonstration of modern authentication (AuthN) and authorization (AuthZ) mechanisms
implemented in a Spring Boot 3 application. It showcases best practices using Spring Security 6, JSON Web Tokens (JWT),
Refresh Tokens, and Role-Based Access Control (RBAC). The goal is to provide a clear, practical, and educational example
of securing a RESTful API.

The project follows principles adapted from Clean Architecture to promote separation of concerns, testability, and
maintainability.

## 2. Architecture

The application structure is loosely based on Clean Architecture principles, dividing the codebase into distinct layers:

* **Domain Layer:** Contains core business entities (`User`, `Role`, `RefreshToken`) and fundamental business rules. It
  has no dependencies on outer layers.
* **Application Layer:** Contains application-specific logic (use cases/services like `AuthService`,
  `RefreshTokenService`), interfaces for repositories and external dependencies (ports), and Data Transfer Objects (
  DTOs). It depends only on the Domain layer.
* **Infrastructure Layer:** Contains implementations of interfaces defined in the Application layer. This includes:
    * `web`: Spring MVC REST Controllers (`AuthController`, `TestController`).
    * `security`: Spring Security configuration (`SecurityConfig`), JWT utilities (`JwtUtils`), filters (
      `JwtAuthFilter`), custom entry points (`AuthEntryPointJwt`), and `UserDetailsService` implementation.
    * `persistence`: Spring Data JPA repository implementations (provided automatically) and database configuration.
    * `config`: General configuration beans (`OpenAPIConfig`, `DataInitializer`).

**Dependency Rule:** Dependencies flow inwards: Infrastructure -> Application -> Domain.

## 3. Technologies Used

* **Backend:** Java 17+, Spring Boot 3.x, Spring Security 6.x
* **Authentication:** JWT (jjwt library), Refresh Tokens
* **Authorization:** Role-Based Access Control (RBAC) via `@PreAuthorize`
* **Database:** H2 (for development), PostgreSQL (configurable)
* **Persistence:** Spring Data JPA, Hibernate
* **API Documentation:** OpenAPI 3 / Swagger UI (via Springdoc)
* **Build:** Maven or Gradle
* **Utilities:** Lombok

## 4. Setup and Running

### Prerequisites

* Java Development Kit (JDK) 17 or newer
* Maven 3.6+ or Gradle 7+
* An IDE (like IntelliJ IDEA, VS Code, Eclipse)
* An API client (like Postman, Insomnia, or `curl`)
* (Optional) Docker and Docker Compose for containerized deployment

### Configuration

1. **JWT Secret:**
    * Open `src/main/resources/application.properties`.
    * Locate the `app.jwt.secret` property.
    * **CRITICAL:** Replace the placeholder value with a strong, secure, Base64-encoded random string of **at least 512
      bits (approx. 86 Base64 characters)**. You can generate one using online tools or code snippets. **Do not commit
      real secrets to version control.** Use environment variables or secrets management in production.
   ```properties
   # Example (REPLACE THIS!):
   app.jwt.secret=yourGeneratedKeyShouldLookSomethingLikeThisButBeRandomlyGeneratedAndAtLeast86CharsLongForBase64a512bit=
   ```
2. **Token Expiration:** Adjust `app.jwt.jwtExpirationInMs` (access token lifetime) and
   `app.jwt.refreshExpirationInMs` (refresh token lifetime) as needed.
3. **Database:** The project defaults to H2 in-memory database. Configuration for PostgreSQL is commented out or can be
   added using Spring profiles (e.g., `application-prod.properties`).

### Running the Application

1. **Clone the repository:** `git clone <repository_url>`
2. **Navigate to the project directory:** `cd auth-demo`
3. **Build the project:**
    * Maven: `mvn clean install`
    * Gradle: `gradle clean build`
4. **Run the application:**
    * Maven: `mvn spring-boot:run`
    * Gradle: `gradle bootRun`
    * Alternatively, run the `main` method in `AuthApplication.java` from your IDE.

The application should start, typically on `http://localhost:8081`.

### Accessing H2 Console (Development)

* Navigate to `http://localhost:8081/h2-console`
* JDBC URL: `jdbc:h2:mem:authdb`
* Username: `sa`
* Password: `password` (or blank if you didn't set one)

### Accessing OpenAPI (Swagger UI)

* Navigate to `http://localhost:8081/swagger-ui.html`

## 5. Authentication (AuthN) Flow

Authentication verifies the identity of a user. This project uses username/password credentials with JWTs.

1. **Registration (`POST /api/auth/register`):**
    * A new user provides username, email, and password.
    * `AuthService` validates input, checks for existing username/email.
    * Password is securely hashed using `BCryptPasswordEncoder`.
    * A `User` entity is created with the default `ROLE_USER`.
    * User is saved to the database.
2. **Login (`POST /api/auth/login`):**
    * User provides username and password.
    * `AuthService` uses Spring Security's `AuthenticationManager` (which internally uses `UserDetailsServiceImpl` and
      `PasswordEncoder`) to validate credentials.
    * If successful:
        * An `Authentication` object is created and set in the `SecurityContextHolder`.
        * A short-lived JWT **Access Token** is generated by `JwtUtils` using the configured secret key and expiration
          time. The token contains user identity information (like username) as claims.
        * A long-lived **Refresh Token** (secure random UUID) is generated/updated by `RefreshTokenService` and stored
          in the database, linked to the user.
        * Both the access token and the refresh token string are returned to the client in the `LoginResponse`.
3. **Accessing Protected Resources:**
    * Client includes the **Access Token** in the `Authorization: Bearer <access_token>` header for subsequent requests
      to protected endpoints.
    * The `JwtAuthFilter` intercepts the request.
    * `JwtUtils.parseJwt` extracts the token from the header.
    * `JwtUtils.validateToken` verifies the token's signature (using the secret key) and checks if it has expired.
    * If valid, the username is extracted using `JwtUtils.getUsernameFromToken`.
    * `UserDetailsServiceImpl.loadUserByUsername` fetches the user's details.
    * An `Authentication` object is created and set in the `SecurityContextHolder`, authenticating the request.
    * The request proceeds to the controller or further security checks (authorization).
4. **Token Refresh (`POST /api/auth/refresh`):**
    * When the Access Token expires, API calls will fail (typically 401 Unauthorized).
    * The client sends the stored **Refresh Token** (the UUID string) in the request body to this endpoint.
    * `AuthService` uses `RefreshTokenService`:
        * Finds the refresh token in the database using the provided string.
        * Verifies the token hasn't expired (`verifyExpiration`).
        * Retrieves the associated `User`.
        * Generates a *new* Access Token using `JwtUtils.generateTokenFromUsername`.
        * (Optional: Implement refresh token rotation by generating/saving a new refresh token and returning it).
        * Returns the new access token (and potentially new refresh token) in `RefreshTokenResponse`.
    * The client stores the new token(s) and retries the original failed API call.
5. **Logout (`POST /api/auth/logout`):**
    * Client sends a request to this endpoint (must include a valid *access token* in the header for authentication).
    * `AuthController` retrieves the authenticated user's ID.
    * `RefreshTokenService.deleteByUserId` removes the user's refresh token from the database.
    * This prevents the user from using their refresh token to get new access tokens.
    * **Note:** Existing *access tokens* remain valid until they expire naturally (stateless nature).

## 6. Authorization (AuthZ) Flow

Authorization determines what actions an authenticated user is allowed to perform. This project uses Role-Based Access
Control (RBAC).

1. **Roles:** Users are assigned roles (e.g., `ROLE_USER`, `ROLE_ADMIN`) stored in the database.
2. **Configuration:**
    * `SecurityConfig` enables method-level security: `@EnableMethodSecurity(prePostEnabled = true)`.
    * The global rule `.anyRequest().authenticated()` ensures users must at least be logged in to access non-public
      endpoints.
3. **Enforcement:**
    * **Method Security:** Annotations like `@PreAuthorize("hasRole('ADMIN')")` or
      `@PreAuthorize("hasAnyRole('USER', 'ADMIN')")` are placed directly on controller methods (or service methods).
    * Spring Security intercepts calls to these methods.
    * It evaluates the SpEL expression in the annotation against the authorities present in the `Authentication`
      object (retrieved from the `SecurityContextHolder`, populated by `JwtAuthFilter`).
    * If the expression evaluates to `true`, the method call proceeds.
    * If `false`, access is denied, typically resulting in an HTTP `403 Forbidden` response.

## 7. API Endpoints

(Access `http://localhost:8081/swagger-ui.html` for interactive documentation)

* **Authentication:**
    * `POST /api/auth/register`: Register a new user.
    * `POST /api/auth/login`: Authenticate and get tokens.
    * `POST /api/auth/refresh`: Refresh access token.
    * `POST /api/auth/logout`: Log out user (invalidate refresh token).
* **Test Authorization:**
    * `GET /api/test/hello`: Requires authentication.
    * `GET /api/test/user`: Requires `ROLE_USER`.
    * `GET /api/test/admin`: Requires `ROLE_ADMIN`.
    * `GET /api/test/all-roles`: Requires `ROLE_USER` or `ROLE_ADMIN`.