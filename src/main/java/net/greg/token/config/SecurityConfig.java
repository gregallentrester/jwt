package net.greg.token.config;

import java.util.List;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.*;

import com.nimbusds.jose.proc.*;

import org.springframework.context.annotation.*;
import org.springframework.security.config.*;
import org.springframework.security.config.annotation.method.configuration.*;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.annotation.web.configuration.*;

import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.*;
import org.springframework.security.config.http.*;

import org.springframework.security.core.userdetails.*;

import org.springframework.security.oauth2.jwt.*;

import org.springframework.security.oauth2.server.resource.web.*;
import org.springframework.security.oauth2.server.resource.web.access.*;

import org.springframework.security.provisioning.*;

import org.springframework.security.web.*;

import org.springframework.web.cors.*;


/*
  https://spring.io/projects/spring-authorization-server
  https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html
  https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html
*/
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

  private final RsaKeyProperties rsaKeys;

  public SecurityConfig(RsaKeyProperties value) {
    rsaKeys = value;
  }


/*
 With a custom security configuration, supply a User
 aside from the default User provided by Spring Boot.

 The following config creates an in-memory User using
 the NoOpPasswordEncoder.

 This password encoder does nothing (useful for testing).
*/
  @Bean
  public InMemoryUserDetailsManager users() {

    return
      new InMemoryUserDetailsManager(
        User.
          withUsername("dvega").
          password("{noop}password").
          authorities("read").
          build());
  }

  /*
  OAUTH 2 RESOURCE SERVER CONFIGURATION
  In your security config, set .oauth2ResourceServer().
  This could be a custom resource server configurer or
  use the SPring OAuth2ResourceServerConfigurer class.

  The OAuth2ResourceServerConfigurer class is an
  AbstractHttpConfigurer for OAuth 2.0 Resource Server Support.

  By default, OAuth2ResourceServerConfigurer wires a
  BearerTokenAuthenticationFilter, which can be used
  to parse the request for bearer-tokens and make an
  authentication attempt.

  The OAuth2ResourceServerConfigurer class has these options:

    accessDeniedHandler         Customizes how access denied errors are handled
    authenticationEntryPoint    Customizes how authentication failures are handled
    bearerTokenResolver         Customizes how to resolve a bearer token from the request
    jwt(Customizer)             Enables Jwt-encoded bearer token support
    opaqueToken(Customizer)     Enables opaque bearer token support

  Using JWT, the configuration option can use a method reference:

    "OAuth2ResourceServerConfigurer::jwt"

  When you use the JWT customizer you need to provide one of the following:

    Supply a Jwk Set Uri via OAuth2ResourceServerConfigurer.JwtConfigurer.jwkSetUri
    Supply a JwtDecoder instance via OAuth2ResourceServerConfigurer.JwtConfigurer.decoder
    Expose a JwtDecoder bean.

  Running the app w/o providing one of the above options following error:

    "Parameter 0 of method setFilterChains() in
    org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration
    required a bean of type 'org.springframework.security.oauth2.jwt.JwtDecoder'
    that could not be found."
  */
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity HTTP) throws Exception {

    return
    HTTP.
    csrf(csrf ->
    csrf.disable()).
    authorizeRequests(
      auth ->
      auth.
        mvcMatchers("/token").permitAll().
        anyRequest().authenticated()
    ).
    sessionManagement(
      session ->
      session.
      sessionCreationPolicy(SessionCreationPolicy.STATELESS)).    // Spring Security never creates
                                                                  // an HttpSession, never uses it
                                                                  // to obtain the Security Context.
      oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt).
      exceptionHandling((ex) ->
        ex.
        authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint()).
        accessDeniedHandler(new BearerTokenAccessDeniedHandler())
    ).
    httpBasic(Customizer.withDefaults()).                         // Spring Security HTTP Basic Authentication
                                                                  // support is enabled by default.
                                                                  // When servlet-based configuration is provided
                                                                  // HTTP Basic must be also explicitly provided.
    build();
  }


  @Bean
  JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
  }


  @Bean
  JwtEncoder jwtEncoder() {

    JWK token =
      new RSAKey.Builder(
        rsaKeys.publicKey()).
          privateKey(
            rsaKeys.privateKey()).build();

    JWKSource<SecurityContext> securityContext =
      new ImmutableJWKSet(new JWKSet(token));

    return new NimbusJwtEncoder(securityContext);
  }


  @Bean
  CorsConfigurationSource corsConfigurationSource() {

    CorsConfiguration config =
      new CorsConfiguration();

    config.setAllowedOrigins(List.of("https://localhost:3000"));
    config.setAllowedHeaders(List.of("*"));
    config.setAllowedMethods(List.of("GET"));

    UrlBasedCorsConfigurationSource configCORS =
      new UrlBasedCorsConfigurationSource();

    configCORS.registerCorsConfiguration("/**", config);

    return configCORS;
  }
}
