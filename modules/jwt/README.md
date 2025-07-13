# practice authentication with JWT

## Signed Jwt JWS

## JWE

JWE stands for Encrypted JWT and is used to protect JWT payload that contains sensitive information.
- The JWE guarantees confidentiality of the payload - no one can see the JWT aside the intended recipient.
- The JWE guarantees integrity of the payload - no one can alter the JWT after it has been encrypted.

JWE achieved this using a special category of encryption called "Authenticated Encryption with Associated Data" (AEAD).

Authenticated Encryption algorithms are all variants of the AES algorithm, which is a symmetric encryption algorithm.
This means that the same key is used for both encryption and decryption of the payload.

NB: Asymmetric encryption algorithms like RSA tends to be slow and for this reason are not used for encrypting the payload in production applications
that could be handling JWT on every HTTP request.

Practice Use Case:

In the context of this practice, since the application is the issuer and receiver of the JWE, the suited encryption technique
is to use a symmetric secret key to encrypt and decrypt the payload.

The algorithm used to encrypt the payload is AES. More specifically the A256GM variant of AES, which uses a 256-bit key for encryption.
I will be providing a base64 string representation of the key, that will be decoded to a 256-bit key before being used to encrypt the payload.

Other Use Cases:

RSA Key Encryption:

In some cases, you may want to use asymmetric encryption algorithms like RSA to encrypt the payload.
A real world example of this is when you want to send a JWT to a third party service that will handle the JWT.

The analogy is:
- AES is like a super strong lock, both the sender and the receiver need the same key to open it.
- Asymmetric encryption algorithms like RSA is a way to safely send the key to the receiver, so they can open the lock.
- RSA is used to encrypt the AES key, and AES is used to encrypt the payload.

The issuer of the JWE will require the public key of the receiver to encrypt the AES key and vice versa.

## Spring Web Security

The practice is about JWT authentication, so it is important to understand how Spring Web Security works.

### Remove Basic Authentication

This is achieved by removing the `BasicAuthenticationFilter` from the filter chain.
Simply omit the `httpBasic()` method in the `securityFilterChain(HttpSecurity http)` method of your security configuration class.

Difference between BasicAuthenticationFilter and UsernamePasswordAuthenticationFilter

- `BasicAuthenticationFilter` is applied to all requests and looks for the `Authorization: Basic ` header in the HTTP request to authenticate and set the user in the security context.
- `UsernamePasswordAuthenticationFilter` is used for login authentication on specific login endpoints and leverages [AuthenticationManager](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/index.html#publish-authentication-manager-bean) to authenticate user via a REST API

### Session Management

Since JWT is stateless, we need to disable session management in Spring Security.

### CSRF Protection

CSRF protection is not needed for stateless JWT authentication, so it can be disabled.