using System;
using System.Diagnostics;

namespace Rijndael
{
    public class PerformanceTest
    {
        public static void TestPowerOptimization()
        {
            Console.WriteLine("=== Performance Test: Power Optimization ===\n");
            
            var gf256 = new GF256Service();
            var irreducibles = gf256.GetAllIrreduciblePolynomials();
            byte modulus = irreducibles[0];
            
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < 10000; i++)
            {
                gf256.Power(0x02, 100, modulus);
            }
            sw.Stop();
            Console.WriteLine($"Fast exponentiation (10k iterations): {sw.ElapsedMilliseconds} ms");
            
            sw.Restart();
            for (int i = 0; i < 10000; i++)
            {
                byte result = 1;
                for (int j = 0; j < 100; j++)
                    result = gf256.Multiply(result, 0x02, modulus);
            }
            sw.Stop();
            Console.WriteLine($"Sequential multiplication (10k iterations): {sw.ElapsedMilliseconds} ms");
            
            byte fastResult = gf256.Power(0x02, 10, modulus);
            byte slowResult = 1;
            for (int i = 0; i < 10; i++)
                slowResult = gf256.Multiply(slowResult, 0x02, modulus);
            
            Console.WriteLine($"\nCorrectness check: Fast={fastResult:X2}, Slow={slowResult:X2}, Match={fastResult == slowResult}");
        }
    }
}