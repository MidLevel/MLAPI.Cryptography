using System;
using System.Diagnostics;
using System.Security.Cryptography;
using MLAPI.Cryptography.KeyExchanges;

namespace MLAPI.Cryptography.Examples
{
    class Program
    {
        public static void Main(string[] args)
        {
            RunECDHERSA(100);
            RunECDHE(100);
        }

        public static void RunECDHERSA(int iterations)
        {
            Console.WriteLine("Running " + iterations + " diffie hellman + rsa key exchanges");

            Stopwatch watch = new Stopwatch();

            RSAParameters privateKey;
            RSAParameters publicKey;

            using (RSACryptoServiceProvider rsaGen = new RSACryptoServiceProvider(2048))
            {
                privateKey = rsaGen.ExportParameters(true);
                publicKey = rsaGen.ExportParameters(false);
            }

            for (int i = 0; i < iterations; i++)
            {
                watch.Start();

                using (RSACryptoServiceProvider serverRSA = new RSACryptoServiceProvider())
                using (RSACryptoServiceProvider clientRSA = new RSACryptoServiceProvider())
                {
                    serverRSA.ImportParameters(privateKey);
                    clientRSA.ImportParameters(publicKey);

                    // Both create their instances
                    ECDiffieHellmanRSA serverDiffie = new ECDiffieHellmanRSA(serverRSA);
                    ECDiffieHellmanRSA clientDiffie = new ECDiffieHellmanRSA(clientRSA);

                    // Exchange publics

                    /* START TRANSMISSION */
                    byte[] serverPublic = serverDiffie.GetSecurePublicPart();
                    byte[] clientPublic = clientDiffie.GetSecurePublicPart();
                    /* END TRANSMISSION */

                    // Calculate shared
                    byte[] key1 = serverDiffie.GetVerifiedSharedPart(clientPublic);
                    byte[] key2 = clientDiffie.GetVerifiedSharedPart(serverPublic);

                    watch.Stop();

                    if (key1.Length != key2.Length)
                    {
                        Console.WriteLine("CRITICAL: LENGTH MISSMATCH");
                        continue;
                    }

                    for (int x = 0; x < key1.Length; x++)
                    {
                        if (key1[x] != key2[x])
                        {
                            Console.WriteLine("CRITICAL: MISSMATCH");
                            break;
                        }
                    }
                }
            }

            Console.WriteLine("Completed in " + watch.ElapsedMilliseconds + " ms, " + (watch.ElapsedMilliseconds / iterations) + " ms per exchange");
        }

        public static void RunECDHE(int iterations)
        {
            Console.WriteLine("Running " + iterations + " diffie hellman key exchanges");

            Stopwatch watch = new Stopwatch();

            for (int i = 0; i < iterations; i++)
            {
                watch.Start();

                // Both create their instances
                ECDiffieHellman serverDiffie = new ECDiffieHellman();
                ECDiffieHellman clientDiffie = new ECDiffieHellman();

                // Exchange publics

                /* START TRANSMISSION */
                byte[] serverPublic = serverDiffie.GetPublicKey();
                byte[] clientPublic = clientDiffie.GetPublicKey();
                /* END TRANSMISSION */

                // Calculate shared
                byte[] key1 = serverDiffie.GetSharedSecretRaw(clientPublic);
                byte[] key2 = clientDiffie.GetSharedSecretRaw(serverPublic);

                watch.Stop();

                if (key1.Length != key2.Length)
                {
                    Console.WriteLine("CRITICAL: LENGTH MISSMATCH");
                    continue;
                }

                for (int x = 0; x < key1.Length; x++)
                {
                    if (key1[x] != key2[x])
                    {
                        Console.WriteLine("CRITICAL: MISSMATCH");
                        break;
                    }
                }
            }

            Console.WriteLine("Completed in " + watch.ElapsedMilliseconds + " ms, " + (watch.ElapsedMilliseconds / iterations) + " ms per exchange");
        }
    }
}
