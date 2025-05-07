package com.example.jokeservice;

import java.util.ArrayList;
import java.util.List;

public class JokeRepository {

    private List<String> jokes;

    public JokeRepository() {
        jokes = new ArrayList<>();

        jokes.add("What do you call a pony with a cough?\n" +
                "\n" +
                "A little horse.");
        jokes.add("What did one hat say to the other?\n" +
                "\n" +
                "You wait here. I’ll go on a head.");
        jokes.add("What do you call a magic dog?\n" +
                "\n" +
                "A labracadabrador.");
        jokes.add("What did the shark say when he ate the clownfish?\n" +
                "\n" +
                "This tastes a little funny.");
        jokes.add("What’s orange and sounds like a carrot?\n" +
                "\n" +
                "A parrot.");
        jokes.add("Why can’t you hear a pterodactyl go to the bathroom?\n" +
                "\n" +
                "Because the “P” is silent.");
        jokes.add("What do you call a woman with one leg?\n" +
                "\n" +
                "Eileen.");
        jokes.add("What did the pirate say when he turned 80?\n" +
                "\n" +
                "Aye matey.");
        jokes.add("Why did the frog take the bus to work today?\n" +
                "\n" +
                "His car got toad away.");
        jokes.add("What did the buffalo say when his son left for college?\n" +
                "\n" +
                "Bison.");
    }

    public List<String> getJokes() {
        return jokes;
    }

    public void setJokes(List<String> jokes) {
        this.jokes = jokes;
    }
}
