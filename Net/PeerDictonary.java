package net;

import model.PeerInfo;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class PeerDirectory {
    private final Map<String, PeerInfo> byShort = new ConcurrentHashMap<>();

    public void addOrUpdate(PeerInfo p) {
        byShort.put(p.shortId(), p);
    }

    public PeerInfo getByShortId(String id) { return byShort.get(id); }

    public List<PeerInfo> list() { return new ArrayList<>(byShort.values()); }
}
