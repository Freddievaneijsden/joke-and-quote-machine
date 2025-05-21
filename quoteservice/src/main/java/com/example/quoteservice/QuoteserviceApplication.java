package com.example.quoteservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@SpringBootApplication
public class QuoteserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(QuoteserviceApplication.class, args);
    }


    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .sessionManagement(AbstractHttpConfigurer::disable) //Does not need it´s own session, new state every time
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/quotes").hasAuthority("SCOPE_read_resource") //
                        //.requestMatchers("/public").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        //Viktig rad ovan - slår på att detta är en resourceServer som ska kunna ta emot tokens.
        return http.build();
    }
}
