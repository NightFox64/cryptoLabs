using System;
using System.Collections.Generic;

namespace Rijndael
{
    public class SimpleTest
    {
        public static void TestBasicGF256()
        {
            Console.WriteLine("=== Basic GF(2^8) Test ===");
            
            var gf256 = new GF256Service();
            
            byte a = 0x53, b = 0xCA;
            byte sum = gf256.Add(a, b);
            Console.WriteLine($"Add: 0x{a:X2} + 0x{b:X2} = 0x{sum:X2}");
            
            Console.WriteLine("Searching for irreducible polynomials...");
            var irreducibles = gf256.GetAllIrreduciblePolynomials();
            Console.WriteLine($"Found {irreducibles.Count} irreducible polynomials");
            
            if (irreducibles.Count > 0)
            {
                Console.WriteLine("First 5 irreducible polynomials:");
                for (int i = 0; i < Math.Min(5, irreducibles.Count); i++)
                {
                    Console.WriteLine($"  0x{irreducibles[i]:X2}");
                }
                
                byte modulus = irreducibles[0];
                Console.WriteLine($"\nTesting with modulus 0x{modulus:X2}:");
                
                try
                {
                    byte product = gf256.Multiply(a, b, modulus);
                    Console.WriteLine($"Multiply: 0x{a:X2} * 0x{b:X2} = 0x{product:X2} (mod 0x{modulus:X2})");
                    
                    byte inverse = gf256.Inverse(a, modulus);
                    Console.WriteLine($"Inverse: 0x{a:X2}^(-1) = 0x{inverse:X2} (mod 0x{modulus:X2})");
                    
                    byte verification = gf256.Multiply(a, inverse, modulus);
                    Console.WriteLine($"Verification: 0x{a:X2} * 0x{inverse:X2} = 0x{verification:X2} (should be 0x01)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("No irreducible polynomials found - there's an issue with the algorithm");
            }
        }
    }
}