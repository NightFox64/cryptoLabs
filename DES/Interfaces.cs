using System;

namespace CryptoLibrary
{
    public interface IKeyExpansion
    {
        byte[][] GenerateRoundKeys(byte[] masterKey);
    }

    public interface IRoundFunction
    {
        byte[] Transform(byte[] inputBlock, byte[] roundKey);
    }

    public interface ISymmetricCipher
    {
        void SetKey(byte[] key);
        byte[] Encrypt(byte[] plaintext);
        byte[] Decrypt(byte[] ciphertext);
    }

    public enum CipherMode
    {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
        CTR,
        RandomDelta
    }

    public enum PaddingMode
    {
        Zeros,
        ANSIX923,
        PKCS7,
        ISO10126
    }
}