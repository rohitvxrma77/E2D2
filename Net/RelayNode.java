package net;

import app.Config;
import model.Envelope;
import model.Message;
import model.PeerInfo;
import store.MemoryVault;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class RelayNode implements AutoCloseable {
    private final Config cfg;
    private final crypto.EphemeralKeyPair self;
    private final PeerDirectory dir;
    private final MemoryVault vault;
    private final AtomicBoolean enabled = new AtomicBoolean(true);

    private final DatagramSocket directSock;
    private final Thread receiverThread;

    public RelayNode(Config cfg, crypto.EphemeralKeyPair self, PeerDirectory dir, MemoryVault vault) throws Exception {
        this.cfg = cfg; this.self = self; this.dir = dir; this.vault = vault;
        this.directSock = new DatagramSocket(cfg.directPort);
        this.receiverThread = new Thread(this::receiveLoop, "direct-recv");
    }

    public void start() { receiverThread.start(); }
    public void setEnabled(boolean on) { enabled.set(on); }

    public void sendDirect(InetSocketAddress addr, Envelope env) throws Exception {
        byte[] bytes = serialize(env);
        DatagramPacket dp = new DatagramPacket(bytes, bytes.length, addr);
        directSock.send(dp);
    }

    private void receiveLoop() {
        byte[] buf = new byte[8192];
        while (!Thread.currentThread().isInterrupted()) {
            try {
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                directSock.receive(dp);
                Envelope env = deserialize(dp.getData(), dp.getOffset(), dp.getLength());
                // Try decrypt for self with any known peer by matching identity
                for (PeerInfo p : dir.list()) {
                    Message m = tryDecryptFrom(p, env);
                    if (m != null) { vault.add(m); break; }
                }
                // If not for us and relay enabled, forward to a random peer (onion style hop)
                if (enabled.get()) {
                    for (PeerInfo p : dir.list()) {
                        if (!p.getAddress().equals(dp.getSocketAddress())) {
                            sendDirect(p.getAddress(), env);
                            break;
                        }
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    private Message tryDecryptFrom(PeerInfo p, Envelope env) {
        // Here you would map Envelope.senderEd25519Der to PeerInfo
        // Simplified: attempt decryption assuming p is sender
        return null; // wire with SecureChannelManager
    }

    private static byte[] serialize(Envelope env) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream o = new ObjectOutputStream(bos)) {
            o.writeObject(env.senderEd25519Der);
            o.writeObject(env.senderX25519Der);
            o.writeObject(env.salt);
            o.writeObject(env.nonce);
            o.writeObject(env.aad);
            o.writeObject(env.ciphertext);
            o.writeObject(env.signature);
        }
        return bos.toByteArray();
    }

    private static Envelope deserialize(byte[] b, int off, int len) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(b, off, len);
        try (ObjectInputStream i = new ObjectInputStream(bis)) {
            return new Envelope(
                (byte[]) i.readObject(),
                (byte[]) i.readObject(),
                (byte[]) i.readObject(),
                (byte[]) i.readObject(),
                (byte[]) i.readObject(),
                (byte[]) i.readObject(),
                (byte[]) i.readObject()
            );
        }
    }

    public void close() {
        receiverThread.interrupt();
        directSock.close();
    }
}
