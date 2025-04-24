package com.snn.auth.infrastructure.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(info = @Info(title = "Auth Demo API", version = "1.0.0",
                                description = "API documentation for the Authentication and Authorization Demo Project.",
                                contact = @Contact(name = "Your Name", email = "your.email@example.com"),
                                license = @License(name = "Apache 2.0",
                                                   url = "http://www.apache.org/licenses/LICENSE-2.0.html")),
                   servers = {@Server(url = "/", description = "Default Server URL")})
@SecurityScheme(name = "bearerAuth",
                description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                scheme = "bearer", type = SecuritySchemeType.HTTP, bearerFormat = "JWT", in = SecuritySchemeIn.HEADER)
public class OpenAPIConfig {}