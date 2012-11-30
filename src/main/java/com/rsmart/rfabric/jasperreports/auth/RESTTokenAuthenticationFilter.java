package com.rsmart.rfabric.jasperreports.auth;

import com.jaspersoft.jasperserver.api.metadata.xml.domain.impl.OperationResult;
import com.jaspersoft.jasperserver.remote.ServicesUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.context.SecurityContextHolder;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 */
public class RESTTokenAuthenticationFilter implements Filter, ApplicationContextAware  {

    private static final Log log = LogFactory.getLog(RESTTokenAuthenticationFilter.class);
    
    public static final String AUTH_TOKEN_HEADER = "x-authn-token";

    private static ApplicationContext applicationContext = null;
    private static ServicesUtils servicesUtils = null;
    
    private AuthenticationManager authenticationManager;

    public void destroy() {
    }
    
    /**
     * Simply grab the authentication token from the request. Does not validate
     * results; i.e. raw data retrieval from request.
     * 
     * @param request
     * @return token
     * @throws IllegalArgumentException
     */
    public final AuthToken getToken (final HttpServletRequest request) {
      log.debug("getToken(final HttpServletRequest request)");
      if (request == null) {
        throw new IllegalArgumentException("request == null");
      }
      return new AuthToken (request.getHeader(AUTH_TOKEN_HEADER));    
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
        throws IOException, ServletException {

    	final HttpServletRequest request = (HttpServletRequest) servletRequest;
    	final HttpServletResponse response = (HttpServletResponse) servletResponse;

      //create credentials
    	AuthToken credential = getToken(request);

    	//create Authentication object
    	AuthTokenAuthentication authToken = new AuthTokenAuthentication(credential);

    	//call authenticationManager.authenticate
      Authentication authResult;
      try {
        authResult = authenticationManager.authenticate(authToken);
      } catch (AuthenticationException e) {
        if (log.isDebugEnabled()) {
          log.debug("Token " + credential + " failed to authenticate: " + e.toString());
        }
        if (log.isWarnEnabled()) {
          log.warn("Token " + credential + " failed to authenticate: " + e.toString() + " " + e, e.getRootCause());
        }

        SecurityContextHolder.getContext().setAuthentication(null);

        // Send an error message in the form of OperationResult...
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        OperationResult or = servicesUtils.createOperationResult(1, "Failed authentication for token " + credential);
        PrintWriter pw = response.getWriter();
        pw.print("Unauthorized");
        return;
      }

      if (log.isDebugEnabled()) {
        log.debug("User " + authToken.getName() + " authenticated: " + authResult);
      }

      SecurityContextHolder.getContext().setAuthentication(authResult);

      chain.doFilter(request, response);
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void setApplicationContext(ApplicationContext ac) throws BeansException {
        applicationContext = ac;
        servicesUtils = ac.getBean(ServicesUtils.class);
    }
    
    public void init(FilterConfig fc) throws ServletException {
    }

}
