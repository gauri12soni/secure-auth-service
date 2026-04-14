package com.gauri.generateToken.security;

import com.gauri.generateToken.entity.Session;
import com.gauri.generateToken.repository.SessionRepository;
import com.gauri.generateToken.service.CustomUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.fasterxml.jackson.databind.ObjectMapper;


import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {


        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = authHeader.substring(7);

            String sessionId = jwtUtil.extractSessionId(token);
            String tokenUsername = jwtUtil.extractUsername(token);


            //  Use findBySessionId
            Session session = sessionRepository.findBySessionId(sessionId)
                    .orElseThrow(() -> new RuntimeException("Session not found"));


            if (session.getExpiresAt().isBefore(Instant.now())) {
                throw new RuntimeException("Session expired");
            }

            // Validate username matches
            if (!session.getUser().getUsername().equals(tokenUsername)) {
                throw new RuntimeException("User mismatch");
            }




            // Store sessionId in request for logout endpoint
            request.setAttribute("sessionId", sessionId);

//            // FIX 2: Update last active time (optional - for tracking)
//            // Only update if more than 5 minutes have passed (to reduce database writes)
            if (session.getLastActive().isBefore(Instant.now().minusSeconds(300))) {
                session.setLastActive(Instant.now());
                sessionRepository.save(session);
            }

            String username = session.getUser().getUsername();

            // SET AUTHENTICATION
            if (username != null &&
                    SecurityContextHolder.getContext().getAuthentication() == null) {

                var userDetails = userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        } catch (ExpiredJwtException e) {
            sendError(response, HttpStatus.UNAUTHORIZED, "Token expired");
            return;

        } catch (Exception e) {
            sendError(response, HttpStatus.UNAUTHORIZED, "Invalid token or session");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void sendError(HttpServletResponse response, HttpStatus status, String message) throws IOException {

        response.setStatus(status.value());
        response.setContentType("application/json");
        objectMapper.writeValue(
                response.getWriter(),
                Map.of("status", status.value(), "message", message)
        );
    }
}