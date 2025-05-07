package com.example.jokeservice;

import java.util.List;

public interface JokeGenerator {
    String getRandomJoke (List<String> jokes);
}
