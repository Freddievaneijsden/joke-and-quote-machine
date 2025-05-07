package com.example.jokeservice;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public interface JokeGenerator {
    void printRandomJoke (Map<Integer, List<String>> jokes) throws InterruptedException;
}
