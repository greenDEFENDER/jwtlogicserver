package com.quantum.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.quantum.authentication.JWTFilter;

@Configuration
public class SecurityConfig {

	@Autowired
	JWTFilter jwtFilter;

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.csrf().disable();
		http.sessionManagement().disable();

		// @formatter:off
		http.authorizeRequests()
			.mvcMatchers("/resource")
			.hasAnyAuthority("modify","ROLE_admin")
			.mvcMatchers("/resources")
			.hasRole("admin")
			.mvcMatchers("/trivial")
			.permitAll()
			.anyRequest()
			.authenticated();
		// @formatter:on
		http.addFilterAt(jwtFilter, BasicAuthenticationFilter.class);

		return http.build();
	}

}
