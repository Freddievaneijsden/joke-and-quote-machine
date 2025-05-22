package com.example.quoteservice.controller;

import com.example.quoteservice.QuoteService;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

@Controller
public class QuoteController {

    QuoteService quoteService;

    public QuoteController(QuoteService quoteService) {
        this.quoteService = quoteService;
    }

    @GetMapping("/random")
    public ResponseEntity<Map<String, String>> getQuote() {
        String quote = quoteService.getRandomQuote();
        Map<String, String> response = Map.of(
                "type", "quote",
                "text", quote
        );
        return ResponseEntity.ok(response);
    }
}
