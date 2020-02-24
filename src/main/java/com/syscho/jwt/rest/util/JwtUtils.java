package com.syscho.jwt.rest.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtUtils {

	@Value("${jwt.secret.key}")
	private String SECRET_KEY;

	public String createToken(String username) {
		Map<String, Object> claims = setClaims();
		return Jwts.builder().addClaims(claims).setSubject(username).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 100 * 60 * 60))
				.signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
	}

	private Map<String, Object> setClaims() {
		Map<String, Object> claims = new HashMap<>();
		claims.put("org", "Syscho");
		return claims;
	}

	public Claims extaractClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
	}

	public <T> T extaractClaim(String token, Function<Claims, T> claimResolver) {
		Claims claims = extaractClaims(token);

		return claimResolver.apply(claims);
	}

	public boolean isTokenExpire(String token) {
		return extaractExpireTime(token).before(new Date());
	}

	public Date extaractExpireTime(String token) {
		return extaractClaim(token, Claims::getExpiration);
	}

	public String extaractUserName(String token) {
		return extaractClaim(token, Claims::getSubject);
	}

	public boolean validateToken(String token, UserDetails user) {
		String extaractUserName = extaractUserName(token);
		return (extaractUserName.equals(user.getUsername()) && !isTokenExpire(token));

	}

}
