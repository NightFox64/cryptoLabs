using System;

namespace CryptoLibrary
{
    public static class BitPermutation
    {
        /// <param name="input">Входное значение</param>
        /// <param name="permutationTable">P-блок (правило перестановки)</param>
        /// <param name="lsbFirst">true - биты индексируются от младшего к старшему, false - наоборот</param>
        /// <param name="zeroBasedIndexing">true - номер начального бита == 0, false - == 1</param>
        /// <returns>Результат перестановки</returns>
        public static byte[] PerformPermutation(byte[] input, int[] permutationTable, bool lsbFirst = true, bool zeroBasedIndexing = true)
        {
            int inputBitLength = input.Length * 8;
            int outputBitLength = permutationTable.Length;
            byte[] output = new byte[(outputBitLength + 7) / 8];

            for (int i = 0; i < outputBitLength; i++)
            {
                int sourceIndex = permutationTable[i];
                if (!zeroBasedIndexing) sourceIndex--;

                bool bitValue = GetBit(input, sourceIndex, lsbFirst);
                SetBit(output, i, bitValue, lsbFirst);
            }

            return output;
        }

        private static bool GetBit(byte[] data, int bitIndex, bool lsbFirst)
        {
            if (bitIndex < 0 || bitIndex >= data.Length * 8)
                return false;
                
            int byteIndex = bitIndex / 8;
            int bitPosition = bitIndex % 8;

            if (!lsbFirst)
                bitPosition = 7 - bitPosition;

            return (data[byteIndex] & (1 << bitPosition)) != 0;
        }

        private static void SetBit(byte[] data, int bitIndex, bool value, bool lsbFirst)
        {
            if (bitIndex < 0 || bitIndex >= data.Length * 8)
                return;
                
            int byteIndex = bitIndex / 8;
            int bitPosition = bitIndex % 8;

            if (!lsbFirst)
                bitPosition = 7 - bitPosition;

            if (value)
                data[byteIndex] |= (byte)(1 << bitPosition);
            else
                data[byteIndex] &= (byte)~(1 << bitPosition);
        }
    }
}