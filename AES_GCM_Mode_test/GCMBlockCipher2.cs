using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES_GCM_Mode_test
{
    public class GCMBlockCipher2
    {
        public static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptWithBouncyCastle(string plaintext, byte[] key)
        {
            const int nonceLength = 12; // in bytes
            const int tagLenth = 16; // in bytes

            var nonce = new byte[nonceLength];
            RandomNumberGenerator.Fill(nonce);

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var bcCiphertext = new byte[plaintextBytes.Length + tagLenth];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), tagLenth * 8, nonce,null);
            
            cipher.Init(true, parameters);

            var offset = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, bcCiphertext, 0);
            cipher.DoFinal(bcCiphertext, offset);

            // Bouncy Castle includes the authentication tag in the ciphertext
            var ciphertext = new byte[plaintextBytes.Length];
            var tag = new byte[tagLenth];
            Buffer.BlockCopy(bcCiphertext, 0, ciphertext, 0, plaintextBytes.Length);
            Buffer.BlockCopy(bcCiphertext, plaintextBytes.Length, tag, 0, tagLenth);

            return (ciphertext, nonce, tag);
        }

        public static string DecryptWithBouncyCastle(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
        {
            var plaintextBytes = new byte[ciphertext.Length];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), tag.Length * 8, nonce,null);
            cipher.Init(false, parameters);

            var bcCiphertext = ciphertext.Concat(tag).ToArray();

            var offset = cipher.ProcessBytes(bcCiphertext, 0, bcCiphertext.Length, plaintextBytes, 0);
            cipher.DoFinal(plaintextBytes, offset);

            return Encoding.UTF8.GetString(plaintextBytes);
        }

    }
}
