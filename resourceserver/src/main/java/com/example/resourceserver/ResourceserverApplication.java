package com.example.resourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@SpringBootApplication
public class ResourceserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceserverApplication.class, args);
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
		http
				//.cors(cors -> cors.configurationSource(corsConfigurationSource)) // Apply CORS configuration
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/secure").hasAuthority("SCOPE_read_resource") // Or just .authenticated()
						.requestMatchers("/public").permitAll()
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
		//Viktig rad ovan - slår på att detta är en resourceServer som ska kunna ta emot tokens.
		return http.build();
	}

}
