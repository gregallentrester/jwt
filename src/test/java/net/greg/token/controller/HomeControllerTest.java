package net.greg.token.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import net.greg.token.config.SecurityConfig;
import net.greg.token.service.TokenService;


@WebMvcTest({HomeController.class, AuthController.class})
@Import({SecurityConfig.class, TokenService.class})
class HomeControllerTest {

  @Autowired
  MockMvc MVC;

  @Test
  void rootWhenUnauthenticatedThen401() throws Exception {

    this.MVC.
      perform(get("/")).
      andExpect(status().
      isUnauthorized());
  }

  @Test
  void rootWhenAuthenticatedThenSaysHelloUser() throws Exception {

    MvcResult result =
      this.MVC.
      perform(post("/token").
      with(httpBasic("dvega", "password"))).
      andExpect(status().isOk()).
      andReturn();

    String token =
      result.getResponse().getContentAsString();

    this.MVC.
      perform(get("/").
      header("Authorization", "Bearer " + token)).
      andExpect(content().string("Hello, dvega"));
  }

  @Test
  @WithMockUser
  public void rootWithMockUserStatusIsOK() throws Exception {

    this.MVC.
      perform(get("/")).
      andExpect(status().
      isOk());
  }
}
