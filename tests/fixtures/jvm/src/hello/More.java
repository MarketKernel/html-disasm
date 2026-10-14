// What Hello.java does not reach, so that every operand kind and every way
// javap prints one is in the fixture: constants of every size and the floats
// Java writes in its own way, strings that need escapes or are not ASCII,
// dense and sparse switches, a switch on strings, every kind of array, the
// stack operations javac uses for x++ and a = b = c, monitors, interfaces,
// inner and anonymous classes, lambdas and method references, a method with
// more locals than a byte can number (the wide forms).
package hello;

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;
import java.util.function.Function;
import java.util.function.Supplier;

public class More implements Comparable<More> {
    interface Shape {
        double area();
        default String name() { return "shape"; }
        static Shape unit() { return () -> 1.0; }
    }

    static final class Circle implements Shape {
        final double r;
        Circle(double r) { this.r = r; }
        public double area() { return Math.PI * r * r; }
        @Override public String name() { return "circle " + Shape.super.name(); }
    }

    sealed interface Expr permits Num, Add {}
    record Num(int value) implements Expr {}
    record Add(Expr left, Expr right) implements Expr {}

    private int count;
    private long total;
    private static int created;
    private volatile boolean done;
    private final Object lock = new Object();
    private int[] counts = new int[4];
    private long[] wide = new long[4];

    class Inner {
        int outerCount() { return count + 1; }
    }

    static long constants() {
        int a = 1000000, b = -129, c = 127, d = -1, e = Integer.MIN_VALUE, f = 5, g = 32767, h = -32768, i = 128;
        long j = 0x123456789ABCDEFL, k = -1L, l = Long.MAX_VALUE, m = 0L, n = 1L, o = 2L;
        float r1 = 1.0f, r2 = 0.1f, r3 = Float.NaN, r4 = Float.POSITIVE_INFINITY, r5 = -0.0f, r6 = 3.4e38f, r7 = 1e-7f, r8 = 2.0f, r9 = 0f, r10 = Float.MIN_VALUE, r11 = 1e7f, r12 = 0.001f;
        double d1 = 2.0, d2 = 0.1, d3 = Double.NEGATIVE_INFINITY, d4 = 1e300, d5 = 123456789.125, d6 = Double.MIN_VALUE, d7 = 0.0, d8 = 1.0, d9 = 1e7, d10 = 1e-3, d11 = 9999999.0, d12 = Double.NaN, d13 = 1e23, d14 = -0.0;
        return a + b + c + d + e + f + g + h + i + j + k + l + m + n + o
            + (long) (r1 + r2 + r3 + r4 + r5 + r6 + r7 + r8 + r9 + r10 + r11 + r12)
            + (long) (d1 + d2 + d3 + d4 + d5 + d6 + d7 + d8 + d9 + d10 + d11 + d12 + d13 + d14);
    }

    static String strings() {
        String s = "tab\there\nnewline \"quoted\" back\\slash 'single' \r\b\f \u0001\u001f\u007f\u0085";
        String u = "Привет, мир — €5 ✓ 😀";
        String empty = "";
        String zero = "nul\u0000byte";
        char ch = 'x';
        return s + u + empty + zero + ch + 'é' + 1.5f + 2.5 + true + 10L + (Object) null;
    }

    static int dense(int x) {
        switch (x) {
            case 1: return 10;
            case 2: return 20;
            case 3: return 30;
            case 5: return 50;
            case 6: return 60;
            default: return -1;
        }
    }

    static int sparse(int x) {
        switch (x) {
            case -1000: return 1;
            case 7: return 2;
            case 100000: return 3;
            case Integer.MAX_VALUE: return 4;
            default: return 0;
        }
    }

    static int words(String s) {
        return switch (s) {
            case "one" -> 1;
            case "two" -> 2;
            case "three" -> 3;
            default -> 0;
        };
    }

    static int eval(Expr e) {
        return switch (e) {
            case Num n -> n.value();
            case Add(Expr l, Expr r) -> eval(l) + eval(r);
        };
    }

    static Object arrays(int n) {
        boolean[] z = new boolean[n];
        char[] c = new char[n];
        float[] f = new float[n];
        double[] d = new double[n];
        byte[] b = new byte[n];
        short[] s = new short[n];
        int[] i = new int[n];
        long[] l = new long[n];
        String[] strs = new String[n];
        int[][] grid = new int[n][n + 1];
        String[][][] cube = new String[2][3][];
        z[0] = true; c[0] = 'a'; f[0] = 1.5f; d[0] = 2.5; b[0] = (byte) 200; s[0] = (short) 70000; i[0] = n; l[0] = n; strs[0] = "s";
        grid[1][2] = 3;
        cube[1][2] = strs;
        int v = i[0]++;
        l[1]++;
        i[1] += 5;
        int k = i[2] = v;
        long q = l[2] = l[0];
        return z[0] ? c[0] + f[0] + d[0] + b[0] + s[0] + i[0] + l[0] + grid.length + cube[1].length + k + q : null;
    }

    int fields(int x) {
        count++;
        total += x;
        this.count = this.count * 2;
        int y = count = x;
        long w = total = y;
        created++;
        --created;
        counts[x & 3]++;
        wide[x & 3] += w;
        return y + (int) w + counts.length;
    }

    static int conversions(int i, long l, float f, double d) {
        byte b = (byte) i;
        char c = (char) i;
        short s = (short) i;
        long a = i + l;
        float g = l + f;
        double h = f + d;
        int r = (int) l + (int) f + (int) d + (int) (l >>> 3) + (i >>> 2) + (i >> 1) + (i << 3);
        long m = (long) f + (long) d + (l << 2) + (l >> 7);
        float n = (float) d + (float) i;
        double o = (double) l;
        return b + c + s + (int) a + (int) g + (int) h + r + (int) m + (int) n + (int) o + (i % 7) + (int) (l % 9) + (int) (f % 2) + (int) (d % 3) + (i / 3) + -i + (i & 5) + (i | 6) + (i ^ 7) + ~i;
    }

    static int compares(int i, long l, float f, double d, Object o, String s) {
        int r = 0;
        if (l > 0) r++;
        if (l <= 5L) r++;
        if (f < 1.0f) r++;
        if (f >= 2.0f) r++;
        if (d > 3.0) r++;
        if (d != 4.0) r++;
        if (d == 5.0) r++;
        if (o == null) r++;
        if (o != s) r++;
        if (o instanceof String t && t.isEmpty()) r++;
        if (i > 10 && i < 20 || i == 30) r++;
        do { r += 2; } while (r < 100);
        outer:
        for (int x = 0; x < 3; x++) for (int y = 0; y < 3; y++) if (x * y == 2) break outer; else r++;
        boolean flag = i > l;
        return flag ? r : -r;
    }

    void locked() {
        synchronized (lock) {
            count++;
        }
        synchronized (More.class) {
            created++;
        }
    }

    static synchronized void lockedStatic() {
        created--;
    }

    static int exceptions(String s) throws IOException {
        try (Closeable c = () -> System.out.println("closed")) {
            return Integer.parseInt(s);
        } catch (NumberFormatException | IllegalStateException e) {
            throw new IOException("bad number: " + s, e);
        } finally {
            created++;
        }
    }

    static void asserts(int x) {
        assert x > 0 : "x must be positive";
        if (x == 42) throw new IllegalArgumentException();
    }

    static Object lambdas(String prefix) {
        Function<String, String> f = s -> prefix + s;
        Supplier<More> make = More::new;
        Function<String, Integer> parse = Integer::parseInt;
        Runnable r = new Runnable() {
            @Override public void run() { System.out.println(prefix); }
        };
        r.run();
        Object[] all = { f, make, parse, Shape.unit(), String[].class, int.class, More.class };
        Arrays.sort(all, (a, b) -> a.hashCode() - b.hashCode());
        return f.apply("x") + parse.apply("12") + make.get().count + all.length;
    }

    static void discard() {
        System.nanoTime();
        System.currentTimeMillis();
        Math.max(1, 2);
        "x".length();
    }

    static int varargs(String... names) {
        return names.length + String.join(",", names).length() + String.format("%d %s", 1, "a").length();
    }

    @Override
    public int compareTo(More other) {
        return Integer.compare(count, other.count);
    }

    static int many() {
        int v0 = 0, v1 = 1, v2 = 2, v3 = 3, v4 = 4, v5 = 5, v6 = 6, v7 = 7, v8 = 8, v9 = 9;
        long w0 = 0, w1 = 1, w2 = 2, w3 = 3, w4 = 4, w5 = 5, w6 = 6, w7 = 7, w8 = 8, w9 = 9;
        double x0 = 0, x1 = 1, x2 = 2, x3 = 3, x4 = 4, x5 = 5, x6 = 6, x7 = 7, x8 = 8, x9 = 9;
        long y0 = 0, y1 = 1, y2 = 2, y3 = 3, y4 = 4, y5 = 5, y6 = 6, y7 = 7, y8 = 8, y9 = 9;
        double z0 = 0, z1 = 1, z2 = 2, z3 = 3, z4 = 4, z5 = 5, z6 = 6, z7 = 7, z8 = 8, z9 = 9;
        long a0 = 0, a1 = 1, a2 = 2, a3 = 3, a4 = 4, a5 = 5, a6 = 6, a7 = 7, a8 = 8, a9 = 9;
        double b0 = 0, b1 = 1, b2 = 2, b3 = 3, b4 = 4, b5 = 5, b6 = 6, b7 = 7, b8 = 8, b9 = 9;
        long c0 = 0, c1 = 1, c2 = 2, c3 = 3, c4 = 4, c5 = 5, c6 = 6, c7 = 7, c8 = 8, c9 = 9;
        double e0 = 0, e1 = 1, e2 = 2, e3 = 3, e4 = 4, e5 = 5, e6 = 6, e7 = 7, e8 = 8, e9 = 9;
        long f0 = 0, f1 = 1, f2 = 2, f3 = 3, f4 = 4, f5 = 5, f6 = 6, f7 = 7, f8 = 8, f9 = 9;
        double g0 = 0, g1 = 1, g2 = 2, g3 = 3, g4 = 4, g5 = 5, g6 = 6, g7 = 7, g8 = 8, g9 = 9;
        long h0 = 0, h1 = 1, h2 = 2, h3 = 3, h4 = 4, h5 = 5, h6 = 6, h7 = 7, h8 = 8, h9 = 9;
        double i0 = 0, i1 = 1, i2 = 2, i3 = 3, i4 = 4, i5 = 5, i6 = 6, i7 = 7, i8 = 8, i9 = 9;
        long j0 = 0, j1 = 1, j2 = 2, j3 = 3, j4 = 4, j5 = 5, j6 = 6, j7 = 7, j8 = 8, j9 = 9;
        int last = 300;
        Object ref = "far";
        float fl = 1.5f;
        long lg = 7;
        double db = 2.5;
        last += 1000;
        last++;
        lg += 1;
        String s = (String) ref;
        return v0 + v9 + (int) (w9 + x9 + y9 + z9 + a9 + b9 + c9 + e9 + f9 + g9 + h9 + i9 + j9) + last + s.length() + (int) fl + (int) lg + (int) db;
    }

    static int strings300() {
        String[] s = {
            "s000", "s001", "s002", "s003", "s004", "s005", "s006", "s007", "s008", "s009", "s010", "s011", "s012", "s013", "s014", "s015", "s016", "s017", "s018", "s019",
            "s020", "s021", "s022", "s023", "s024", "s025", "s026", "s027", "s028", "s029", "s030", "s031", "s032", "s033", "s034", "s035", "s036", "s037", "s038", "s039",
            "s040", "s041", "s042", "s043", "s044", "s045", "s046", "s047", "s048", "s049", "s050", "s051", "s052", "s053", "s054", "s055", "s056", "s057", "s058", "s059",
            "s060", "s061", "s062", "s063", "s064", "s065", "s066", "s067", "s068", "s069", "s070", "s071", "s072", "s073", "s074", "s075", "s076", "s077", "s078", "s079",
            "s080", "s081", "s082", "s083", "s084", "s085", "s086", "s087", "s088", "s089", "s090", "s091", "s092", "s093", "s094", "s095", "s096", "s097", "s098", "s099",
            "s100", "s101", "s102", "s103", "s104", "s105", "s106", "s107", "s108", "s109", "s110", "s111", "s112", "s113", "s114", "s115", "s116", "s117", "s118", "s119",
            "s120", "s121", "s122", "s123", "s124", "s125", "s126", "s127", "s128", "s129", "s130", "s131", "s132", "s133", "s134", "s135", "s136", "s137", "s138", "s139",
        };
        float big = 123.25f;
        return s.length + (int) big + 100000 + (int) 3.75f;
    }
}
