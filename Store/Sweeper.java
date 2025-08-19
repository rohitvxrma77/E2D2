package store;

public class Sweeper {
    private final MemoryVault vault;
    private final Thread t;

    public Sweeper(MemoryVault v) {
        this.vault = v;
        this.t = new Thread(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    Thread.sleep(1000);
                    vault.sweep();
                }
            } catch (InterruptedException ignored) {}
        }, "vault-sweeper");
    }

    public void start() { t.start(); }
}
