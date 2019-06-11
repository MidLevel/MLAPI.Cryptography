using System;
using System.Diagnostics;
using MLAPI.Cryptography.KeyExchanges;

namespace MLAPI.Cryptography.Examples
{
    class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Running 100 diffie hellman key exchanges");

            Stopwatch watch = new Stopwatch();

            for (int i = 0; i < 100; i++)
            {
                watch.Start();

                // Both create their instances
                ECDiffieHellman serverDiffie = new ECDiffieHellman(ECDiffieHellman.DEFAULT_CURVE, ECDiffieHellman.DEFAULT_GENERATOR, ECDiffieHellman.DEFAULT_ORDER);
                ECDiffieHellman clientDiffie = new ECDiffieHellman(ECDiffieHellman.DEFAULT_CURVE, ECDiffieHellman.DEFAULT_GENERATOR, ECDiffieHellman.DEFAULT_ORDER);

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

            Console.WriteLine("Completed in " + watch.ElapsedMilliseconds + " ms, " + (watch.ElapsedMilliseconds / 100) + " ms per exchange");
        }
    }
}
