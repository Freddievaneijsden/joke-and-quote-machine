package com.example.jokeservice;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Random;

@Service
public class JokeService implements JokeGenerator{

    JokeRepository jokeRepository = new JokeRepository();
    Random random = new Random();

    @Override
    public List<String> getRandomJoke() {
        int randomNumber = random.nextInt(0, 9);

        return jokeRepository.getIndexedJokes().get(randomNumber);
    }
}
