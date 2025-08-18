package net;

import app.Config;
import crypto.Sign;
import model.PeerInfo;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DiscoveryListener implements AutoCloseable {
    private final Config cfg;
    private final crypto.EphemeralKeyPair self;
    private final PeerDirectory dir;
    private final MulticastSocket sock;
    private final Thread thread;

    public DiscoveryListener(Config cfg, crypto.EphemeralKeyPair self, PeerDirectory dir) throws Exception {
        this.cfg = cfg; this.self = self; this.dir = dir;
        this.sock = new MulticastSocket(cfg.multicastPort);
        InetAddress group = InetAddress.getByName(cfg.multicastGroup);
        sock.joinGroup(group);
        this.thread = new Thread(this::run, "discovery-listener");
    }

    public void start() { thread.start(); }

    private void run() {
        byte[] buf = new byte[4096];
        while (!Thread.currentThread().isInterrupted()) {
            try {
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                sock.receive(dp);
                String s = new String(dp.getData(), dp.getOffset(), dp.getLength());
                String[] parts = s.split("\\|");
                if (parts.length != 4) continue;
                if (!"HELLO".equals(parts)) continue;

                byte[] edDer = Base64.getDecoder().decode(parts);
                byte[] xDer = Base64.getDecoder().decode(parts);
                byte[] sig = Base64.getDecoder().decode(parts);

                KeyFactory kf = KeyFactory.getInstance("Ed25519");
                PublicKey edPub = kf.generatePublic(new X509EncodedKeySpec(edDer));
                boolean ok = Sign.verify(edPub, (parts+"|"+parts+"|"+parts).getBytes(), sig);
                if (!ok) continue;

                KeyFactory kfx = KeyFactory.getInstance("XDH");
                PublicKey xPub = kfx.generatePublic(new X509EncodedKeySpec(xDer));

                PeerInfo p = new PeerInfo(edDer, xPub, edPub, new java.net.InetSocketAddress(dp.getAddress(), cfg.directPort));
                dir.addOrUpdate(p);
            } catch (Exception ignored) {}
        }
    }

    public void close() {
        thread.interrupt();
        sock.close();
    }
}
