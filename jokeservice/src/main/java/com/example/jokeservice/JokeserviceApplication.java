package com.example.jokeservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@SpringBootApplication
public class JokeserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(JokeserviceApplication.class, args);
    }

    @Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
		http
				.sessionManagement(AbstractHttpConfigurer::disable) //Does not need it´s own session, new state every time
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/random").hasAuthority("SCOPE_read_resource")
						.anyRequest().authenticated()

				)
				.oauth2ResourceServer(oauth2 -> oauth2
						.jwt(Customizer.withDefaults())
				);

		return http.build();
	}

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
//                .csrf(csrf -> csrf.disable());
//        return http.build();
//    }


}
