package df.root;

/**
 * Process-wide copy of the exploit output, so a dedicated screen can show it in
 * full even though the main page only has a cramped strip (wear screens are
 * tiny). Bounded so a long run cannot grow without limit.
 */
final class OutputLog {

    private static final StringBuilder BUF = new StringBuilder();
    private static final int MAX_CHARS = 64 * 1024;

    private OutputLog() {}

    static synchronized void append(String s) {
        BUF.append(s);
        if (BUF.length() > MAX_CHARS)
            BUF.delete(0, BUF.length() - MAX_CHARS);
    }

    static synchronized String get() {
        return BUF.toString();
    }

    static synchronized void clear() {
        BUF.setLength(0);
    }
}
