// What hello.cs does not reach, so that every operand kind and every way
// ildasm prints one is in the fixture: constants of every size, strings that
// need escapes or are not ASCII, a dense switch, exception filters and fault
// handlers (an iterator's), function pointers and calli, stackalloc, generic
// classes and constraints, multi-dimensional arrays, P/Invoke, names ildasm
// quotes.
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace Hello.More;

public sealed class Box<T> where T : struct
{
    private T value;
    private static int created;
    public volatile int Version;
    public Box(T value) { this.value = value; Interlocked.Increment(ref created); }
    public T Value { get => value; set { this.value = value; Version++; } }
    public TOut Map<TOut>(Func<T, TOut> f) => f(value);
    public override string ToString() => value.ToString() ?? "";
    public static int Size() => Unsafe.SizeOf<T>();
}

public interface IShape { double Area(); string Name => "shape"; }
public record Circle(double R) : IShape { public double Area() => Math.PI * R * R; }

public static unsafe class Edge
{
    [DllImport("libc", EntryPoint = "abs")]
    private static extern int Abs(int value);

    public static long Constants()
    {
        int a = 1000000, b = -129, c = 127, d = -1, e = int.MinValue;
        long f = 0x123456789ABCDEFL, g = -1L, h = long.MaxValue;
        float r1 = 1.0f, r2 = 0.1f, r3 = float.NaN, r4 = float.PositiveInfinity, r5 = -0.0f, r6 = 3.4e38f, r7 = 1e-7f;
        double d1 = 2.0, d2 = 0.1, d3 = double.NegativeInfinity, d4 = 1e300, d5 = 123456789.125, d6 = 5e-324;
        return a + b + c + d + e + f + g + h + (long)(r1 + r2 + r3 + r4 + r5 + r6 + r7 + d1 + d2 + d3 + d4 + d5 + d6);
    }

    public static void Strings(System.IO.TextWriter w)
    {
        w.Write("tab\there \"quoted\" back\\slash\r\nnew line");
        w.Write("Привет, мир");
        w.Write("\0nul\u0001\a\b\f\v");
        w.Write("emoji 😀");
        w.Write("?question?? 'single' \u007f del");
        w.Write("");
        w.Write("a very long string that goes on and on, longer than any line ildasm likes to print in one piece, so that it has to be cut into parts joined with a plus sign, and then some more words to be sure of it");
    }

    public static int Switch(int n)
    {
        switch (n)
        {
            case 0: return 10;
            case 1: return 11;
            case 2: return 12;
            case 3: return 13;
            case 5: return 15;
            case 6: return 16;
            default: return -1;
        }
    }

    public static int Filter(string s)
    {
        try { return int.Parse(s); }
        catch (FormatException e) when (e.Message.Length > 3) { return -1; }
        catch (OverflowException) { return -2; }
    }

    public static IEnumerable<int> Count(int n)
    {
        try { for (int i = 0; i < n; i++) yield return i; }
        finally { Console.WriteLine("done"); }
    }

    static int Twice(int x) => x * 2;

    public static int Pointers(int x)
    {
        delegate*<int, int> twice = &Twice;
        delegate* unmanaged[Cdecl]<int, int> abs = (delegate* unmanaged[Cdecl]<int, int>)0;
        int* buffer = stackalloc int[16];
        buffer[3] = twice(x);
        nint size = sizeof(Circle*);
        Span<byte> bytes = stackalloc byte[8];
        return buffer[3] + (int)size + bytes.Length + (abs == null ? Abs(-x) : abs(x));
    }

    public static int Arrays()
    {
        var grid = new int[3, 4];
        grid[1, 2] = 7;
        var jagged = new int[2][];
        jagged[0] = new[] { 1, 2 };
        object o = grid;
        Type t = typeof(Dictionary<string, List<int>>);
        if (o is int[,] g && o as string == null) return g[1, 2] + jagged[0]![1] + t.Name.Length + (int)(object)5;
        return ((int[,])o).Length;
    }

    public static int Five(int a, int b, int c, int d, int value, int @object, ref int method, out int field)
    {
        field = value + @object;
        method += 1;
        return a + b + c + d + value;
    }

    public static string Generic<T>(T item) where T : IShape => item.Name + item.Area().ToString("F1") + default(T)?.ToString() + sizeof(Point);

    public static decimal Money(decimal m) => m * 1.5m;

    public static ulong Unsigned(uint a, ulong b, byte c, ushort d) => checked(a + b + c + d) / (b == 0 ? 1 : b) >> 3;

    public static void Locks(object gate) { lock (gate) { Console.WriteLine(Environment.TickCount); } }

    public static (int, string) Tuple() => (1, "one");
}
