using System.Numerics;

namespace RSA;

public static class MathService
{
    public static int LegendreSymbol(BigInteger a, BigInteger p)
    {
        if (p <= 1 || p % 2 == 0) throw new ArgumentException("p must be odd prime > 1");
        
        a %= p;
        if (a == 0) return 0;
        
        var result = ModularPow(a, (p - 1) / 2, p);
        return result == p - 1 ? -1 : (int)result;
    }

    public static int JacobiSymbol(BigInteger a, BigInteger n)
    {
        if (n <= 0 || n % 2 == 0) throw new ArgumentException("n must be positive odd");
        
        a %= n;
        int result = 1;
        
        while (a != 0)
        {
            while (a % 2 == 0)
            {
                a /= 2;
                if (n % 8 == 3 || n % 8 == 5) result = -result;
            }
            
            (a, n) = (n, a);
            if (a % 4 == 3 && n % 4 == 3) result = -result;
            a %= n;
        }
        
        return n == 1 ? result : 0;
    }

    public static BigInteger Gcd(BigInteger a, BigInteger b)
    {
        a = BigInteger.Abs(a);
        b = BigInteger.Abs(b);
        
        while (b != 0)
        {
            var temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    public static (BigInteger gcd, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b)
    {
        if (b == 0) return (a, 1, 0);
        
        var (gcd, x1, y1) = ExtendedGcd(b, a % b);
        var x = y1;
        var y = x1 - (a / b) * y1;
        
        return (gcd, x, y);
    }

    public static BigInteger ModularPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
    {
        if (modulus == 1) return 0;
        
        BigInteger result = 1;
        baseValue %= modulus;
        
        while (exponent > 0)
        {
            if (exponent % 2 == 1)
                result = (result * baseValue) % modulus;
            
            exponent >>= 1;
            baseValue = (baseValue * baseValue) % modulus;
        }
        
        return result;
    }
}