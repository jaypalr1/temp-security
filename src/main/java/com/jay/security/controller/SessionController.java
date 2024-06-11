package com.jay.security.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SessionController {

  @GetMapping("/session-max-interval")
  public String retrieveMaxSessionInactiveInterval(HttpSession session) {
    return "Max Inactive Interval before Session expires: " + session.getMaxInactiveInterval();
  }
}
