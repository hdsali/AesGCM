// See https://aka.ms/new-console-template for more information
using AES_GCM_Mode_test;


namespace main
{
    namespace TestAES_GCM_256
    {
        class Program
        {

            public static void Main(string[] args)
            {
                while (true)
                {
                    ProcessEncryptDecrypt();
                }
            }
            public static void ProcessEncryptDecrypt()
            {
                int iChoice = 0;
                string strPwd = string.Empty;
                string strKey = string.Empty;
                var encryptedString = string.Empty;
                Console.WriteLine("Enter your choice:");
                Console.WriteLine("1.Encryption   2.Decryption  3.Exit ");
                Console.WriteLine("******************************");

                iChoice = Convert.ToInt32(Console.ReadLine());




                if (iChoice == 1)
                {
                    Console.WriteLine("Enter the Password:");

                    strPwd = Convert.ToString(Console.ReadLine());
                    encryptedString = AesGcm256.encrypt(strPwd);
                    Console.WriteLine($"encrypted string = {encryptedString}");


                }
                else if (iChoice == 2)
                {
                    Console.WriteLine("Enter the Password:");
                    strPwd = Convert.ToString(Console.ReadLine());
                    var decryptedString = AesGcm256.decrypt(strPwd);
                    Console.WriteLine($"decrypted string = {decryptedString}");
                }
                
                else
                {
                    Environment.Exit(0);
                }
            }
        }
    }


}
