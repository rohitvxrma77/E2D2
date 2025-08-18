package crypto;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

public class NonceSeq {
    private final AtomicLong ctr = new AtomicLong(1);
    private final byte[] base; // 4 bytes random + 8 bytes counter -> 12 bytes

    public NonceSeq(byte[] base4) {
        if (base4.length != 4) throw new IllegalArgumentException();
        this.base = Arrays.copyOf(base4, 12);
    }

    public synchronized byte[] next() {
        long v = ctr.getAndIncrement();
        for (int i = 0; i < 8; i++) base[4+i] = (byte)((v >>> (56 - 8*i)) & 0xFF);
        return Arrays.copyOf(base, 12);
    }
}
