package app;

import java.net.InetSocketAddress;

public class Config {
    public final String multicastGroup;
    public final int multicastPort;
    public final int relayPort;
    public final int directPort;

    public Config(String g, int mPort, int relayPort, int directPort) {
        this.multicastGroup = g;
        this.multicastPort = mPort;
        this.relayPort = relayPort;
        this.directPort = directPort;
    }

    public static Config defaultConfig() {
        return new Config("239.12.12.12", 55055, 55056, 55057);
    }

    public InetSocketAddress multicastSocket() {
        return new InetSocketAddress(multicastGroup, multicastPort);
    }
}
