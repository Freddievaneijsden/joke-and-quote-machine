package com.example.resourceserver;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

//    @CrossOrigin(origins = "http://localhost:8888") Fast way of allowing CORS instead of own config
    @GetMapping("/secure")
    public String secureEndpoint() {
        return "Hello from the SECURE Resource Server! Token is valid.";
    }

    @GetMapping("/public")
    public String publicEndpoint() {
        return "Hello from the PUBLIC Resource Server!";
    }
}
