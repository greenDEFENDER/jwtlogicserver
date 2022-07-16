package com.quantum.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTFilter extends OncePerRequestFilter {

	@Autowired
	AuthenticationServerProxy proxy;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// intercepting all request and authorizing.
		String jwt = request.getHeader("Authorization");
		if (jwt == null || jwt.isEmpty()) {
			response.sendError(401, "NO TOKEN FOUND");
			return;
		}

		String username = getUsernameFromJwt(jwt);

		// getting secret of user from authorization server
		String userSecret = proxy.getSecret(username);

		// getting authorities of user after verifying jwt token with user secret.
		List<SimpleGrantedAuthority> authorities = null;
		try {
			authorities = mapStringAuthoritiesToAuthorities(validateAndGetStringAuthorities(userSecret, jwt));
		} catch (Exception e) {
			response.sendError(401, "INVALID TOKEN");
			return;
		}

		// creating authentication object and placing it in SecurityContext
		// so spring security can use it for authentication.
		Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
		SecurityContextHolder.getContext().setAuthentication(auth);

		// authentication done.
		filterChain.doFilter(request, response);
	}

	private String getUsernameFromJwt(String jwt) {
		int i = jwt.lastIndexOf('.');
		String jwtWithoutSignature = jwt.substring(0, i + 1);

		// @formatter:off
		Claims untrusted = Jwts.parserBuilder()
				.build()
				.parseClaimsJwt(jwtWithoutSignature)
				.getBody();
		// @formatter:on

		String username = untrusted.get("username").toString();

		return username;
	}

	// validating token signature and getting its payload after validating.
	@SuppressWarnings({ "unchecked" })
	private List<String> validateAndGetStringAuthorities(String secret, String jwt) {
		SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

		// @formatter:off
		Claims claims = Jwts.parserBuilder()
						.setSigningKey(key)
						.build()
						.parseClaimsJws(jwt)
						.getBody();
		// @formatter:on

		return (List<String>) claims.get("authorities");
	}

	// mapping string authorities to GrantedAuthorities objects.
	private List<SimpleGrantedAuthority> mapStringAuthoritiesToAuthorities(List<String> roles) {

		List<SimpleGrantedAuthority> authorities = new ArrayList<>();
		for (String role : roles)
			authorities.add(new SimpleGrantedAuthority(role));

		return authorities;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

		if (request.getRequestURI().contains("/trivial"))
			return true;

		return false;
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<String> handleException(Exception ex) {
		return new ResponseEntity<String>("IT SEEMS TOKEN IS INVALID", HttpStatus.NOT_ACCEPTABLE);
	}

}
