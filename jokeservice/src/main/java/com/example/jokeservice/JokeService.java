package com.example.jokeservice;

import java.util.List;
import java.util.Random;

public class JokeService implements JokeGenerator{

    Random random = new Random();

    @Override
    public String getRandomJoke(List<String> jokes) {
        int randomNumber = random.nextInt(0, 10);

        return jokes.get(randomNumber);
    }
}
