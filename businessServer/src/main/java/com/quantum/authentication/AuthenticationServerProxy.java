package com.quantum.authentication;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class AuthenticationServerProxy {

	RestTemplate restTemplate = new RestTemplate();

	public String getSecret(String username) {

		return restTemplate.getForObject("http://localhost:9999/secret/{username}", String.class, username);
	}

}
