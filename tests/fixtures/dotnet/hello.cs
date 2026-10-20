// The same program as hello.c, in C#, for the CIL decoder's tests: strings,
// calls into the base library, generics, a switch, exceptions, a struct,
// a delegate, an async method and a little unsafe code.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Hello;

public enum Kind { Small, Medium, Large }

public struct Point
{
    public int X, Y;
    public Point(int x, int y) { X = x; Y = y; }
    public readonly long Length2 => (long)X * X + (long)Y * Y;
}

public static class Program
{
    static long Sum(int[] values, int count)
    {
        long total = 0;
        for (int i = 0; i < count; i++) total += values[i];
        return total;
    }

    static string KindOf(long sum) => (sum % 4) switch
    {
        0 => "zero",
        1 => "one",
        2 => "two",
        _ => "many",
    };

    static Kind Classify(double value)
    {
        if (value < 1.5) return Kind.Small;
        if (value <= 100.25) return Kind.Medium;
        return Kind.Large;
    }

    static unsafe int Checksum(byte[] data)
    {
        int sum = 0;
        fixed (byte* p = data)
        {
            for (int i = 0; i < data.Length; i++) sum = (sum << 1) ^ p[i];
        }
        return sum;
    }

    static T Largest<T>(List<T> items) where T : IComparable<T>
    {
        T best = items[0];
        foreach (var item in items) if (item.CompareTo(best) > 0) best = item;
        return best;
    }

    static async Task<int> CountAsync(int n)
    {
        await Task.Yield();
        return n * 2;
    }

    public static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--help")
        {
            Console.WriteLine("usage: hello [numbers...]");
            return 0;
        }
        int[] values = { 1, 2, 3, 4, 5, 6, 7, 8 };
        long sum = Sum(values, values.Length);
        double avg = (double)sum / values.Length;
        Console.WriteLine($"Hello, world! sum={sum} avg={avg:F2} kind={KindOf(sum)}");
        var p = new Point(3, 4);
        Func<int, int> twice = x => x * 2;
        try
        {
            checked { sum += twice(p.X) * int.Parse(args.Length > 1 ? args[1] : "7"); }
        }
        catch (FormatException e)
        {
            Console.Error.WriteLine(e.Message);
        }
        finally
        {
            Console.WriteLine(Classify(avg));
        }
        var list = new List<string> { "pear", "apple", "fig" };
        Console.WriteLine(Largest(list) + " " + p.Length2 + " " + Checksum(new byte[] { 1, 2, 3 }));
        return CountAsync((int)sum).GetAwaiter().GetResult() > 0 ? 0 : 1;
    }
}
