package app;

import crypto.EphemeralKeyPair;
import model.Envelope;
import model.Message;
import model.PeerInfo;
import net.*;
import store.MemoryVault;
import store.Sweeper;
import util.Clock;

import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class Cli {
    private final Config config = Config.defaultConfig();
    private final EphemeralKeyPair id = EphemeralKeyPair.generate();
    private final PeerDirectory peers = new PeerDirectory();
    private final MemoryVault vault = new MemoryVault(new Clock(), 1024);
    private final DiscoveryBroadcaster broadcaster = new DiscoveryBroadcaster(config, id);
    private final DiscoveryListener listener = new DiscoveryListener(config, id, peers);
    private final RelayNode relay = new RelayNode(config, id, peers, vault);
    private final SecureChannelManager channels = new SecureChannelManager(id);

    public void start(String[] args) throws Exception {
        System.out.println("E2D2 — Ephemeral Encrypted Dead Drop");
        System.out.println("ID: " + Base64.getEncoder().encodeToString(id.getPublicKeyEncoded()));
        broadcaster.start();
        listener.start();
        relay.start();
        new Sweeper(vault).start();

        Scanner sc = new Scanner(System.in);
        loop: while (true) {
            System.out.println("\n- peers\n- send <peerId> <ttlSec> <text>\n- sendfile <peerId> <ttlSec> <path>\n- recv\n- relay on|off\n- quit");
            System.out.print("> ");
            String line = sc.nextLine().trim();
            if (line.equals("peers")) {
                List<PeerInfo> ps = peers.list();
                ps.forEach(p -> System.out.println(p.shortId()+" "+p.getAddress()));
            } else if (line.startsWith("sendfile ")) {
                String[] parts = line.split("\\s+", 4);
                if (parts.length < 4) { System.out.println("usage: sendfile <peerId> <ttlSec> <path>"); continue; }
                PeerInfo p = peers.getByShortId(parts[1]);
                if (p == null) { System.out.println("peer not found"); continue; }
                long ttl = Long.parseLong(parts);
                byte[] data = Files.readAllBytes(Path.of(parts));
                Message m = Message.file("application/octet-stream", data, System.currentTimeMillis()+ttl*1000);
                Envelope env = channels.encryptFor(p, m);
                relay.sendDirect(p.getAddress(), env);
                System.out.println("sent " + data.length + " bytes");
            } else if (line.startsWith("send ")) {
                String[] parts = line.split("\\s+", 4);
                if (parts.length < 4) { System.out.println("usage: send <peerId> <ttlSec> <text>"); continue; }
                PeerInfo p = peers.getByShortId(parts);
                if (p == null) { System.out.println("peer not found"); continue; }
                long ttl = Long.parseLong(parts);
                Message m = Message.text(parts, System.currentTimeMillis()+ttl*1000);
                Envelope env = channels.encryptFor(p, m);
                relay.sendDirect(p.getAddress(), env);
                System.out.println("sent");
            } else if (line.equals("recv")) {
                List<Message> msgs = vault.drain();
                if (msgs.isEmpty()) System.out.println("no messages");
                else msgs.forEach(m -> {
                    if (m.isText()) System.out.println("[text] " + m.getText());
                    else System.out.println("[file] " + m.getMime() + " " + m.getData().length + "B");
                });
            } else if (line.equals("relay on")) {
                relay.setEnabled(true);
                System.out.println("relay enabled");
            } else if (line.equals("relay off")) {
                relay.setEnabled(false);
                System.out.println("relay disabled");
            } else if (line.equals("quit")) {
                break loop;
            } else {
                System.out.println("unknown command");
            }
        }
        broadcaster.close();
        listener.close();
        relay.close();
        System.out.println("bye");
    }
}
