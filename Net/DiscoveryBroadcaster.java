package net;

import app.Config;
import crypto.EphemeralKeyPair;
import crypto.Sign;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Timer;
import java.util.TimerTask;

public class DiscoveryBroadcaster implements AutoCloseable {
    private final Config cfg;
    private final EphemeralKeyPair id;
    private final MulticastSocket sock;
    private final InetAddress group;
    private final Timer timer = new Timer(true);

    public DiscoveryBroadcaster(Config cfg, EphemeralKeyPair id) throws Exception {
        this.cfg = cfg; this.id = id;
        this.sock = new MulticastSocket();
        this.group = InetAddress.getByName(cfg.multicastGroup);
    }

    public void start() {
        timer.scheduleAtFixedRate(new TimerTask() {
            public void run() {
                try {
                    byte[] ed = id.getEdPublic().getEncoded();
                    byte[] x = id.getXPublic().getEncoded();
                    byte[] msg = ("HELLO|" + Base64.getEncoder().encodeToString(ed) + "|" + Base64.getEncoder().encodeToString(x)).getBytes();
                    byte[] sig = crypto.Sign.sign(id.getEdPrivate(), msg);
                    byte[] packet = new byte[msg.length + 1 + sig.length];
                    System.arraycopy(msg, 0, packet, 0, msg.length);
                    packet[msg.length] = '|';
                    System.arraycopy(sig, 0, packet, msg.length+1, sig.length);
                    DatagramPacket dp = new DatagramPacket(packet, packet.length, group, cfg.multicastPort);
                    sock.send(dp);
                } catch (Exception ignored) {}
            }
        }, 0, 2000);
    }

    public void close() {
        timer.cancel();
        sock.close();
    }
}
