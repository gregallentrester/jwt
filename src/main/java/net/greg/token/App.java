package net.greg.token;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import net.greg.token.config.RsaKeyProperties;

/*
 Login:
  Username: 'user'
  Password: is generated, it should be listed in the console output.

 https://www.danvega.dev/blog/2022/09/06/spring-security-jwt/
 */
@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
public class App {

  public static void main(String[] args) {
    SpringApplication.run(App.class, args);
  }
}
