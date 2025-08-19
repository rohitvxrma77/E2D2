package model;

import java.net.InetSocketAddress;
import java.security.PublicKey;

public class PeerInfo {
    private final byte[] ed25519Der; // identity
    private final PublicKey xPub;
    private final PublicKey edPub;
    private final InetSocketAddress address;

    public PeerInfo(byte[] id, PublicKey xPub, PublicKey edPub, InetSocketAddress addr) {
        this.ed25519Der = id; this.xPub = xPub; this.edPub = edPub; this.address = addr;
    }

    public String shortId() {
        int h = 0;
        for (byte b: ed25519Der) h = (h*31) ^ (b & 0xFF);
        h ^= (h >>> 16);
        return Integer.toHexString(h);
    }

    public byte[] getIdentity() { return ed25519Der; }
    public PublicKey getXPub() { return xPub; }
    public PublicKey getEdPub() { return edPub; }
    public InetSocketAddress getAddress() { return address; }
}
