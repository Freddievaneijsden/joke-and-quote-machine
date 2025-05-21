package com.example.quoteservice.controller;

import com.example.quoteservice.QuoteService;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class QuoteController {

    QuoteService quoteService;

    public QuoteController(QuoteService quoteService) {
        this.quoteService = quoteService;
    }

    @GetMapping("/quotes")
    public ResponseEntity<String> getQuote() {
        String quote = quoteService.getRandomQuote();
        return ResponseEntity.ok(quote);
    }
}
