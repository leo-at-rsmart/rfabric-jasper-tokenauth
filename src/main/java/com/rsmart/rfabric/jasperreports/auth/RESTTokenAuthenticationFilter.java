package com.rsmart.rfabric.jasperreports.auth;

import com.jaspersoft.jasperserver.api.metadata.xml.domain.impl.OperationResult;
import com.jaspersoft.jasperserver.remote.ServicesUtils;

import org.apache.commons.lang.CharEncoding;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.ui.WebAuthenticationDetails;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;

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
import java.net.URLDecoder;

/**
 */
public class RESTTokenAuthenticationFilter implements Filter, ApplicationContextAware  {

    private static final Log log = LogFactory.getLog(RESTTokenAuthenticationFilter.class);
    private static ApplicationContext applicationContext = null;
    private static ServicesUtils servicesUtils = null;
    
    private AuthenticationManager authenticationManager;
    private String authenticationFailureUrl;
    private String[] excludeUrls;
    private String sharedSecret;

    public void destroy() {
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
        throws IOException, ServletException {

      if (sharedSecret == null) {
        log.warn("DISABLED: no sharedSecret has been set");
        chain.doFilter(servletRequest, servletResponse);
        return;
      }
      
    	final HttpServletRequest request = (HttpServletRequest) servletRequest;
    	final HttpServletResponse response = (HttpServletResponse) servletResponse;

    	AuthToken authToken = new AuthToken(sharedSecret, request);

    	//create credentials
    	//call authenticationManager.authenticate
    	
      Authentication authResult;
      try {
        authResult = authenticationManager.authenticate(authToken);
      } catch (AuthenticationException e) {
        final String claimedId = authToken.getClaimedUserId();
        
        if (log.isDebugEnabled()) {
          log.debug("User " + claimedId + " failed to authenticate: " + e.toString());
        }
        if (log.isWarnEnabled()) {
          log.warn("User " + claimedId + " failed to authenticate: " + e.toString() + " " + e, e.getRootCause());
        }

        SecurityContextHolder.getContext().setAuthentication(null);

        // Send an error message in the form of OperationResult...
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        OperationResult or = servicesUtils.createOperationResult(1, "Invalid username " + claimedId);
        PrintWriter pw = response.getWriter();
        pw.print("Unauthorized");
        return;
      }

      if (log.isDebugEnabled()) {
        log.debug("User " + authToken.getValidatedUserId() + " authenticated: " + authResult);
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
      if (!applicationContext.containsBean("sharedSecret")) {
        log.error ("DISABLED: no 'sharedSecret' has been set in the Spring application context");
      } else {
        sharedSecret = (String) applicationContext.getBean("sharedSecret");
      }
    }

}
