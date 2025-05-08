package com.example.quoteservice;

import java.util.Map;
import java.util.Random;

public class QuoteService implements QuoteGenerator{

    Random random = new Random();
    QuoteRepository quoteRepository = new QuoteRepository();

    @Override
    public String getRandomQuote() {
        int randomNumber = random.nextInt(0, 10);

        return quoteRepository.getQuotes().get(randomNumber);
    }
}
