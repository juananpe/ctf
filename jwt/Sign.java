package com.isad.bertsioak;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;


public class Sign {

	public static void main(String[] args) throws IOException {
		
	//	 Path path = Paths.get("/tmp/key");
		 Path path = Paths.get("/tmp/public.pem");
		 
		
		String s = Jwts.builder()
				.claim("login", "admin")
				.signWith(SignatureAlgorithm.HS256, Files.readAllBytes(path))
				.compact();

		
		
		System.out.println(s);
		//auth=eyJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6ImFkbWluIn0.FOfozMzQCAd87BaT6wVRUZdFMeNTFYQZeZSK0dSBom8
	}
}

