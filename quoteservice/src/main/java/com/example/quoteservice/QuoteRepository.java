package com.example.quoteservice;

import java.util.HashMap;
import java.util.Map;

public class QuoteRepository {

    Map<Integer, String> quotes = new HashMap<>();
    int index = 0;

    public QuoteRepository() {
        quoteMapper("“Be yourself; everyone else is already taken.”\n" +
                "― Oscar Wilde");
        quoteMapper("“I'm selfish, impatient and a little insecure. I make mistakes, I am out of control and at times hard to handle. But if you can't handle me at my worst, then you sure as hell don't deserve me at my best.”\n" +
                "― Marilyn Monroe");
        quoteMapper("“So many books, so little time.”\n" +
                "― Frank Zappa");
        quoteMapper("“Two things are infinite: the universe and human stupidity; and I'm not sure about the universe.”\n" +
                "― Albert Einstein");
        quoteMapper("“A room without books is like a body without a soul.”\n" +
                "― Marcus Tullius Cicero");
        quoteMapper("“Be who you are and say what you feel, because those who mind don't matter, and those who matter don't mind.”\n" +
                "― Bernard M. Baruch");
        quoteMapper("“You know you're in love when you can't fall asleep because reality is finally better than your dreams.”\n" +
                "― Dr. Seuss");
        quoteMapper("“You only live once, but if you do it right, once is enough.”\n" +
                "― Mae West");
        quoteMapper("“Be the change that you wish to see in the world.”\n" +
                "― Mahatma Gandhi");
        quoteMapper("“In three words I can sum up everything I've learned about life: it goes on.”\n" +
                "― Robert Frost");
    }

    private void quoteMapper(String quote) {
        quotes.put(index, quote);

        index += 1;
    }

    public Map<Integer, String> getQuotes() {
        return quotes;
    }

    public void setQuotes(Map<Integer, String> quotes) {
        this.quotes = quotes;
    }
}
