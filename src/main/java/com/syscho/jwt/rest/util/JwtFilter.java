package com.syscho.jwt.rest.util;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import com.syscho.jwt.rest.service.UserDetailsServiceImpl;

@Service
public class JwtFilter extends OncePerRequestFilter {

	@Autowired
	JwtUtils jwtUtils;

	@Autowired
	UserDetailsServiceImpl service;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String jwtToken = null;
		String username = null;

		final String authTokenHeader = request.getHeader("Authorization");
		if (Objects.nonNull(authTokenHeader) && authTokenHeader.startsWith("Bearer ")) {
			jwtToken = authTokenHeader.substring(7);
			username = jwtUtils.extaractUserName(jwtToken);

		}

		if (Objects.nonNull(username) && !Objects.nonNull(SecurityContextHolder.getContext().getAuthentication())) {

			System.out.print("*****************************");
			UserDetails userDetails = service.loadUserByUsername(username);

			if (jwtUtils.validateToken(jwtToken, userDetails)) {
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}
		filterChain.doFilter(request, response);

	}

}
