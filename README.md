# keycloak-authenticator-verify-new-browser
Keycloak Authenticator Verify new browser

## How to build
```
./mvnw clean package
```

## How to Run for local dev
```
./mvnw clean package && docker-compose up --build
```

### Sign In demonstration

1. Move to http://localhost:8080/auth/realms/master/account/#/personal-info
    1. Input `admin` to [Username or email]
    2. Input `admin1234` to [Password]
    3. Click [Sign In] button
2. Move to http://localhost:8025/ and Click [Inbox] link
    1. Open email and Click `Verify login by new browser` link in body of text that starts with
       `http://localhost:8080/auth/realms/master/login-actions/action-token?`

### Registration demonstration
1. Move to http://localhost:8080/auth/realms/master/account/#/personal-info and Click [Register] link
    1. Input `Charlie` to [First name]
    2. Input `Test` to [Last name]
    3. Input `test@localhost` to [Email]
    4. Input `test` to [Username]
    5. Input `test1234` to [Password]
    6. Input `test1234` to [Confirm password]
    7. Click [Register] button
