package com.quantum.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.quantum.authentication.AuthenticationServerProxy;

@RestController
public class BusinessController {

	@Autowired
	AuthenticationServerProxy proxy;

	@GetMapping("/test")
	public String test() {
		return "booyaahhh I am working";
	}

	@GetMapping("/resource")
	public String resource() {
		return "tutflix is a very good website for free courses";
	}

	@GetMapping("/resources")
	public String resources() {
		return "welcome you have authority admin";
	}

	@GetMapping("/trivial")
	public String trivial() {
		return "Narendra Modi is a Feku man";
	}

}
