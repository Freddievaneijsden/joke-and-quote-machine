package com.example.jokeservice;

import java.util.List;
import java.util.Map;
import java.util.Random;

public class JokeService implements JokeGenerator{

    Random random = new Random();

    @Override
    public void printRandomJoke(Map<Integer, List<String>> jokes) throws InterruptedException {
        int randomNumber = random.nextInt(0, 10);

        List<String> joke = jokes.get(randomNumber);

        System.out.println(joke.get(0));

        Thread.sleep(2500);
        System.out.println(joke.get(1));
    }
}
