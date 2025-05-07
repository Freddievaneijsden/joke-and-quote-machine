package com.example.jokeservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JokeserviceApplication {

    public static void main(String[] args) throws InterruptedException {
        SpringApplication.run(JokeserviceApplication.class, args);

        JokeService jokeService = new JokeService();
        JokeRepository jokeRepository = new JokeRepository();

        jokeService.printRandomJoke(jokeRepository.getIndexedJokes());
    }

}
