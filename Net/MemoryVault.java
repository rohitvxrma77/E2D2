package store;

import model.Message;
import util.Clock;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

public class MemoryVault {
    private final Clock clock;
    private final int max;
    private final Queue<Message> q = new ConcurrentLinkedQueue<>();

    public MemoryVault(Clock clock, int max) { this.clock = clock; this.max = max; }

    public void add(Message m) {
        if (q.size() >= max) q.poll();
        if (m.getExpiresAtMs() > clock.now()) q.add(m);
    }

    public List<Message> drain() {
        List<Message> out = new ArrayList<>();
        Message m;
        while ((m=q.poll()) != null) if (m.getExpiresAtMs() > clock.now()) out.add(m);
        return out;
    }

    public void sweep() {
        q.removeIf(m -> m.getExpiresAtMs() <= clock.now());
    }
}
