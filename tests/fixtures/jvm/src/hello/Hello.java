// The same program as hello.c, in Java, for the JVM decoder's tests: strings,
// calls into the class library, generics, a switch, exceptions, a record,
// a lambda, string concatenation and a little arithmetic of every width.
package hello;

import java.util.ArrayList;
import java.util.List;
import java.util.function.IntUnaryOperator;

public class Hello {
    enum Kind { SMALL, MEDIUM, LARGE }

    record Point(int x, int y) {
        long length2() { return (long) x * x + (long) y * y; }
    }

    static long sum(int[] values, int count) {
        long total = 0;
        for (int i = 0; i < count; i++) total += values[i];
        return total;
    }

    static String kindOf(long sum) {
        return switch ((int) (sum % 4)) {
            case 0 -> "zero";
            case 1 -> "one";
            case 2 -> "two";
            default -> "many";
        };
    }

    static Kind classify(double value) {
        if (value < 1.5) return Kind.SMALL;
        if (value <= 100.25) return Kind.MEDIUM;
        return Kind.LARGE;
    }

    static int checksum(byte[] data) {
        int sum = 0;
        for (int i = 0; i < data.length; i++) sum = (sum << 1) ^ (data[i] & 0xff);
        return sum;
    }

    static <T extends Comparable<T>> T largest(List<T> items) {
        T best = items.get(0);
        for (T item : items) if (item.compareTo(best) > 0) best = item;
        return best;
    }

    public static void main(String[] args) {
        if (args.length > 0 && args[0].equals("--help")) {
            System.out.println("usage: hello [numbers...]");
            return;
        }
        int[] values = { 1, 2, 3, 4, 5, 6, 7, 8 };
        long sum = sum(values, values.length);
        double avg = (double) sum / values.length;
        System.out.println("Hello, world! sum=" + sum + " avg=" + String.format("%.2f", avg) + " kind=" + kindOf(sum));
        Point p = new Point(3, 4);
        IntUnaryOperator twice = x -> x * 2;
        try {
            sum = Math.addExact(sum, twice.applyAsInt(p.x()) * Integer.parseInt(args.length > 1 ? args[1] : "7"));
        } catch (NumberFormatException e) {
            System.err.println(e.getMessage());
        } finally {
            System.out.println(classify(avg));
        }
        List<String> list = new ArrayList<>(List.of("pear", "apple", "fig"));
        System.out.println(largest(list) + " " + p.length2() + " " + checksum(new byte[] { 1, 2, 3 }));
        System.exit(sum > 0 ? 0 : 1);
    }
}
