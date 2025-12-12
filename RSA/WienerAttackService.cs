using System.Numerics;

namespace RSA;

public static class WienerAttackService
{
    public record WienerAttackResult(
        BigInteger? D,
        BigInteger? Phi,
        List<(BigInteger Numerator, BigInteger Denominator)> ContinuedFractions
    );

    public static WienerAttackResult PerformAttack(RSAPublicKey publicKey)
    {
        var continuedFractions = new List<(BigInteger, BigInteger)>();
        var convergents = GetConvergents(publicKey.E, publicKey.N, continuedFractions);

        foreach (var (k, d) in convergents)
        {
            if (k == 0 || d == 0) continue;

            if ((publicKey.E * d - 1) % k != 0) continue;
            var phi = (publicKey.E * d - 1) / k;

            if (IsValidPhi(publicKey.N, phi))
            {
                return new WienerAttackResult(d, phi, continuedFractions);
            }
        }

        return new WienerAttackResult(null, null, continuedFractions);
    }

    private static List<(BigInteger, BigInteger)> GetConvergents(BigInteger e, BigInteger n, List<(BigInteger, BigInteger)> continuedFractions)
    {
        var convergents = new List<(BigInteger, BigInteger)>();
        var quotients = new List<BigInteger>();

        var a = e;
        var b = n;
        
        while (b != 0)
        {
            var q = a / b;
            quotients.Add(q);
            var temp = b;
            b = a % b;
            a = temp;
        }

        BigInteger p_prev = 0, p_curr = 1;
        BigInteger q_prev = 1, q_curr = 0;

        for (int i = 0; i < quotients.Count; i++)
        {
            var q = quotients[i];
            var p_next = q * p_curr + p_prev;
            var q_next = q * q_curr + q_prev;

            continuedFractions.Add((p_next, q_next));
            convergents.Add((q_next, p_next));

            p_prev = p_curr;
            p_curr = p_next;
            q_prev = q_curr;
            q_curr = q_next;
        }

        return convergents;
    }

    private static bool IsValidPhi(BigInteger n, BigInteger phi)
    {
        if (phi <= 0 || phi >= n) return false;

        var discriminant = (n - phi + 1) * (n - phi + 1) - 4 * n;
        
        if (discriminant < 0) return false;

        var sqrtDiscriminant = BigIntegerSqrt(discriminant);
        if (sqrtDiscriminant * sqrtDiscriminant != discriminant) return false;

        var sum = n - phi + 1;
        if ((sum + sqrtDiscriminant) % 2 != 0) return false;

        var p = (sum + sqrtDiscriminant) / 2;
        var q = (sum - sqrtDiscriminant) / 2;

        return p * q == n && p > 1 && q > 1;
    }

    private static BigInteger BigIntegerSqrt(BigInteger n)
    {
        if (n == 0) return 0;
        var x = n;
        var y = (n + 1) / 2;
        while (y < x)
        {
            x = y;
            y = (x + n / x) / 2;
        }
        return x;
    }
}