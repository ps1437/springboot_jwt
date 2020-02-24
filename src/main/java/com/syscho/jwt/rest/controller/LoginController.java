package com.syscho.jwt.rest.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.syscho.jwt.rest.util.JwtUtils;
import com.syscho.jwt.rest.vo.LoginReq;

@RestController
public class LoginController {

	@Autowired
	JwtUtils jwtUtils;

	@Autowired
	AuthenticationManager authMgr;

	@PostMapping("/auth/login")
	public ResponseEntity<Object> doAuthentication(@RequestBody LoginReq login) {
		Authentication authenticate = authMgr
				.authenticate(new UsernamePasswordAuthenticationToken(login.getUserName(), login.getPassword()));

		if (authenticate.isAuthenticated()) {

			String token = jwtUtils.createToken(authenticate.getName());

			return ResponseEntity.ok().header("token", token).body("Auth Successful");
		}
		return ResponseEntity.badRequest().body("Auth Failed");

	}

	@PostMapping("/auth/logout")
	public String doLogOut() {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication.isAuthenticated()) {
			authentication.setAuthenticated(false);

		}
		return "Logout Successful";

	}

	@GetMapping("/info")
	public String info() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		return "Welcome " + authentication.getName() + " !!";

	}
}
