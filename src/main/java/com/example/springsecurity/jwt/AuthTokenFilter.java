package com.example.springsecurity.jwt;

import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component // if we write component, then it is spring managed class, so we can use Autowired annotation to pass the bean, without it, we cant use Autowired


// This OncePerRequestFilter runs once only with every request
public class AuthTokenFilter extends OncePerRequestFilter {
// We created our own custom filter

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.debug("AuthTokenFiler is called for URI {}", request.getRequestURI());

        try {
            String jwt = parseJwt(request);
            if(jwt!=null && jwtUtils.validateJWTToken(jwt)){
                String username = jwtUtils.getUsernameFromJWTToken(jwt);  // Getting the username from token
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);  // Getting the userdetails from the username

                // Then we will create an authentication object, which needs to be set in security context. To mark the request as authenticated

                // This is an authentication object
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,null,userDetails.getAuthorities()
                );


                // we are attaching the request details to the authentication object, so like whatever the request have it is passed on to the authentication object
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // We need to set this object to the Security Content of spring security
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                logger.debug("Roles from JWT : {}", userDetails.getAuthorities());

            }
        }
        catch (Exception e){
            logger.error("Cannot set user authentication :{}",e);
        }

        // this specifies spring security to continue filter chain and execute any filters that are pending
        filterChain.doFilter(request, response); // with this all the rest of the filters other than this custom authentication one will continue executing normally
    }


    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFiler.java : {}", jwt);
        return jwt;
    }
}
