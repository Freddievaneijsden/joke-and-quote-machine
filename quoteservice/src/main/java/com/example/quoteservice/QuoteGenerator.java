package com.example.quoteservice;

import java.util.Map;

public interface QuoteGenerator {

    String getRandomQuote(Map<Integer, String> quotes);
}
