package com.jay.security.interceptors;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SessionFilter implements Filter {

  private static final String DASH = "=======================================";

  @Override
  public void init(FilterConfig filterConfig) {
    System.out.println(DASH + "\nInit filter \n" + DASH);
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse res = (HttpServletResponse) response;
    Cookie[] allCookies = req.getCookies();

    if (allCookies != null) {
      Cookie session = Arrays.stream(allCookies).filter(x -> x.getName().equals("JSESSIONID"))
          .findFirst()
          .orElse(null);

      if (session != null) {
        session.setHttpOnly(true);
        session.setSecure(true);
        res.addCookie(session);
      }
    }

    chain.doFilter(req, res);
  }

  @Override
  public void destroy() {
    System.out.println(DASH + "\nDestroy filter \n" + DASH);
  }
}
