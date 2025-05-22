package com.example.jokeservice.controller;

import com.example.jokeservice.JokeService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.util.List;
import java.util.Map;

@Controller
public class JokeController {

    JokeService jokeService;

    public JokeController(JokeService jokeService) {
        this.jokeService = jokeService;
    }

//    @GetMapping("/index")
//    public String tellAJoke(Model model) {
//        List<String> joke = jokeService.getRandomJoke();
//        model.addAttribute("premise", joke.get(0));
//        model.addAttribute("punchline", joke.get(1));
//        return "joke";
//    }

    @GetMapping("/jokes")
    public ResponseEntity<Map<String, String>> tellAJoke(Authentication authentication) {
        System.out.println("User authenticated as: " + authentication.getName());
        List<String> joke = jokeService.getRandomJoke();
        Map<String, String> response = Map.of("premise", joke.get(0), "punchline", joke.get(1));
        return ResponseEntity.ok(response);
    }
}
