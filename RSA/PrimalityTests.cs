using System.Numerics;

namespace RSA;

public interface IPrimalityTest
{
    bool IsPrime(BigInteger n, double minProbability);
}

public abstract class PrimalityTestBase : IPrimalityTest
{
    private static readonly Random _random = new();

    public bool IsPrime(BigInteger n, double minProbability)
    {
        if (minProbability < 0.5 || minProbability >= 1.0)
            throw new ArgumentException("Probability must be in [0.5, 1)");

        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;

        int iterations = CalculateIterations(minProbability);
        
        for (int i = 0; i < iterations; i++)
        {
            if (!PerformSingleTest(n)) return false;
        }
        return true;
    }

    protected abstract bool PerformSingleTest(BigInteger n);

    private static int CalculateIterations(double minProbability)
    {
        var iterations = (int)Math.Ceiling(Math.Log(1 - minProbability) / Math.Log(0.5));
        return Math.Min(iterations, 10);
    }

    protected static BigInteger GetRandomBigInteger(BigInteger min, BigInteger max)
    {
        if (min >= max) throw new ArgumentException("min must be less than max");
        
        var range = max - min;
        var bytes = range.ToByteArray();
        if (bytes[^1] == 0) bytes = bytes[..^1];
        
        BigInteger result;
        do
        {
            _random.NextBytes(bytes);
            bytes[^1] &= 0x7F;
            result = new BigInteger(bytes);
        } while (result >= range);
        
        return result + min;
    }
}

public class FermatTest : PrimalityTestBase
{
    protected override bool PerformSingleTest(BigInteger n)
    {
        if (n <= 3) return n > 1;
        var a = GetRandomBigInteger(2, n - 1);
        return MathService.ModularPow(a, n - 1, n) == 1;
    }
}

public class SolovayStrassenTest : PrimalityTestBase
{
    protected override bool PerformSingleTest(BigInteger n)
    {
        if (n <= 3) return n > 1;
        var a = GetRandomBigInteger(2, n - 1);
        var jacobi = MathService.JacobiSymbol(a, n);
        if (jacobi == 0) return false;
        
        var power = MathService.ModularPow(a, (n - 1) / 2, n);
        var expected = jacobi == -1 ? n - 1 : (BigInteger)jacobi;
        
        return power == expected;
    }
}

public class MillerRabinTest : PrimalityTestBase
{
    protected override bool PerformSingleTest(BigInteger n)
    {
        var d = n - 1;
        int r = 0;
        while (d % 2 == 0)
        {
            d /= 2;
            r++;
        }

        var a = GetRandomBigInteger(2, n - 1);
        var x = MathService.ModularPow(a, d, n);
        
        if (x == 1 || x == n - 1) return true;
        
        for (int i = 0; i < r - 1; i++)
        {
            x = MathService.ModularPow(x, 2, n);
            if (x == n - 1) return true;
        }
        return false;
    }
}