using System;
using System.Collections.Generic;

namespace Rijndael
{
    public class ReducibleModulusException : Exception
    {
        public ReducibleModulusException(string message) : base(message) { }
    }

    public class GF256Service
    {
        public byte Add(byte a, byte b) => (byte)(a ^ b);

        public byte Multiply(byte a, byte b, byte modulus)
        {
            if (!IsIrreducible(modulus))
                throw new ReducibleModulusException($"Modulus {modulus:X2} is reducible");

            if (a == 0 || b == 0) return 0;

            int result = 0;
            int temp = a;

            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                    result ^= temp;
                
                bool overflow = (temp & 0x80) != 0;
                temp <<= 1;
                
                if (overflow)
                    temp ^= modulus;
                
                b >>= 1;
            }

            return (byte)result;
        }

        public byte Inverse(byte element, byte modulus)
        {
            if (!IsIrreducible(modulus))
                throw new ReducibleModulusException($"Modulus {modulus:X2} is reducible");

            if (element == 0)
                throw new ArgumentException("Zero has no inverse");

            int a = modulus | 0x100;
            int b = element;
            int u = 0, v = 1;

            while (b != 0)
            {
                int q = DividePolynomialsWithQuotient(a, b, out int remainder);
                a = b;
                b = remainder;
                int newU = u ^ MultiplyPolynomials(q, v);
                u = v;
                v = newU;
            }

            return (byte)(u & 0xFF);
        }

        public bool IsIrreducible(byte polynomial)
        {
            int poly = polynomial | 0x100; 
            
            for (int divisor = 2; divisor < 256; divisor++)
            {
                if (poly != divisor && DividePolynomials(poly, divisor) == 0)
                    return false;
            }

            return true;
        }

        public List<byte> GetAllIrreduciblePolynomials()
        {
            var result = new List<byte>();
            
            for (int poly = 0; poly <= 0xFF; poly++)
            {
                if (IsIrreducible((byte)poly))
                    result.Add((byte)poly);
            }

            return result;
        }

        public byte Power(byte baseElement, int exponent, byte modulus)
        {
            if (!IsIrreducible(modulus))
                throw new ReducibleModulusException($"Modulus {modulus:X2} is reducible");

            if (exponent == 0) return 1;
            if (exponent == 1 || baseElement == 0) return baseElement;

            byte result = 1;
            byte currentBase = baseElement;

            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                    result = Multiply(result, currentBase, modulus);
                
                currentBase = Multiply(currentBase, currentBase, modulus);
                exponent >>= 1;
            }

            return result;
        }

        public List<byte> FactorizePolynomial(int polynomial)
        {
            var factors = new List<byte>();
            var irreducibles = GetAllIrreduciblePolynomials();

            foreach (var factor in irreducibles)
            {
                while (polynomial % factor == 0)
                {
                    factors.Add(factor);
                    polynomial /= factor;
                }
            }

            if (polynomial > 1)
                factors.Add((byte)polynomial);

            return factors;
        }

        private int DividePolynomials(int dividend, int divisor)
        {
            if (divisor == 0 || dividend == 0) return dividend;

            int remainder = dividend;
            int divisorDegree = GetDegree(divisor);
            
            while (GetDegree(remainder) >= divisorDegree && remainder != 0)
            {
                int shift = GetDegree(remainder) - divisorDegree;
                remainder ^= divisor << shift;
            }

            return remainder; 
        }

        private int DividePolynomialsWithQuotient(int dividend, int divisor, out int remainder)
        {
            if (divisor == 0)
            {
                remainder = dividend;
                return 0;
            }

            int quotient = 0;
            remainder = dividend;
            int divisorDegree = GetDegree(divisor);
            
            while (GetDegree(remainder) >= divisorDegree && remainder != 0)
            {
                int shift = GetDegree(remainder) - divisorDegree;
                quotient ^= 1 << shift;
                remainder ^= divisor << shift;
            }

            return quotient;
        }

        private int MultiplyPolynomials(int a, int b)
        {
            int result = 0;
            while (b != 0)
            {
                if ((b & 1) != 0)
                    result ^= a;
                a <<= 1;
                b >>= 1;
            }
            return result;
        }

        private int GetDegree(int polynomial)
        {
            if (polynomial == 0) return -1;
            int degree = 0;
            while (polynomial > 1)
            {
                polynomial >>= 1;
                degree++;
            }
            return degree;
        }
    }
}