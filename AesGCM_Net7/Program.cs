// See https://aka.ms/new-console-template for more information

namespace AesGCM.Net7
{
    class Program
    {
        static void Main(string[] args)
        {
            var password = "TestPassword";
            var plaintext = "TestPlainText";

            if (args.Length > 0) plaintext = args[0];
            if (args.Length > 1) password = args[1];
            try
            {
                var keygen = new System.Security.Cryptography.Rfc2898DeriveBytes(password, 64, 10000);  //
                var key = keygen.GetBytes(32);
                var aesGcm = new System.Security.Cryptography.AesGcm(key);

                var plainBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);

                var IV = keygen.GetBytes(12);
                var tag = new byte[16];

                var associatedData = new byte[12];
                var cipherText = new byte[plainBytes.Length];

                aesGcm.Encrypt(IV, plainBytes, cipherText, tag, associatedData);


                var plain = new byte[cipherText.Length];

                aesGcm.Decrypt(IV, cipherText, tag, plain, associatedData);

                Console.WriteLine("Plaintext: {0}", plaintext);
                Console.WriteLine("Password: {0}", password);

                Console.WriteLine("IV: {0} [{1}]", Convert.ToBase64String(IV), Convert.ToHexString(IV));
                Console.WriteLine("Key: {0} [{1}]", Convert.ToBase64String(key), Convert.ToHexString(key));
                Console.WriteLine("\nCipher: {0} [{1}]", Convert.ToBase64String(cipherText), Convert.ToHexString(cipherText));
                Console.WriteLine("Plain text: {0}", System.Text.Encoding.UTF8.GetString(plain));
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }

        }
    }
}
