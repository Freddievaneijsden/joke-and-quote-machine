package com.example.jokeservice.controller;

import com.example.jokeservice.JokeService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.util.List;

@Controller
public class JokeController {

    JokeService jokeService;

    public JokeController(JokeService jokeService) {
        this.jokeService = jokeService;
    }

    @GetMapping("/index")
    public String tellAJoke(Model model) {
        List<String> joke = jokeService.getRandomJoke();
        model.addAttribute("premise", joke.get(0));
        model.addAttribute("punchline", joke.get(1));
        return "joke";
    }
}
