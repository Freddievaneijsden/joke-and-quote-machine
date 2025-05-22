package com.example.quoteservice;

import org.springframework.stereotype.Service;

import java.util.Random;

@Service
public class QuoteService implements QuoteGenerator{

    Random random = new Random();
    QuoteRepository quoteRepository = new QuoteRepository();

    @Override
    public String getRandomQuote() {
        int randomNumber = random.nextInt(0, 9);

        return quoteRepository.getQuotes().get(randomNumber);
    }
}
