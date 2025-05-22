package com.example.jokeservice;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JokeRepository {

    private Map<Integer, List<String>> indexedJokes = new HashMap<>();
    private int index = 0;

    public JokeRepository() {
        jokeMapper("What do you call a pony with a cough?", "A little horse.");
        jokeMapper("What did one hat say to the other?", "You wait here. I’ll go on a head.");
        jokeMapper("What do you call a magic dog?", "A labracadabrador.");
        jokeMapper("What did the shark say when he ate the clownfish?", "This tastes a little funny.");
        jokeMapper("What’s orange and sounds like a carrot?", "A parrot.");
        jokeMapper("Why can’t you hear a pterodactyl go to the bathroom?", "Because the “P” is silent.");
        jokeMapper("What do you call a woman with one leg?", "Eileen.");
        jokeMapper("What did the pirate say when he turned 80?", "Aye matey.");
        jokeMapper("Why did the frog take the bus to work today?", "His car got toad away.");
        jokeMapper("What did the buffalo say when his son left for college?", "Bison.");
    }

    private void jokeMapper (String premise, String punchline) {
        List<String> newList = new ArrayList<>();
        newList.add(premise);
        newList.add(punchline);

        indexedJokes.put(index, newList);

        index ++;
    }

    public Map<Integer, List<String>> getIndexedJokes() {
        return indexedJokes;
    }

    public void setIndexedJokes(Map<Integer, List<String>> indexedJokes) {
        this.indexedJokes = indexedJokes;
    }
}
