using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MLAPI.Cryptography.Utils;

namespace MLAPI.Cryptography.KeyExchanges
{
    public class ECDiffieHellmanRSA
    {
        private readonly ECDiffieHellman _diffieHellanInstance = new ECDiffieHellman();
        private readonly RSACryptoServiceProvider _rsa;

        private bool _isSigner => !_rsa.PublicOnly;

        public ECDiffieHellmanRSA(X509Certificate2 certificate)
        {
            if (certificate.HasPrivateKey)
            {
                _rsa = certificate.PrivateKey as RSACryptoServiceProvider;
            }
            else
            {
                _rsa = certificate.PublicKey.Key as RSACryptoServiceProvider;
            }

            if (_rsa == null)
            {
                throw new CryptographicException("Only RSA certificates are supported. No valid RSA key was found");
            }
        }

        public ECDiffieHellmanRSA(RSACryptoServiceProvider rsa)
        {
            _rsa = rsa;

            if (_rsa == null)
            {
                throw new CryptographicException("Key cannot be null");
            }
        }

        public byte[] GetSecurePublicPart()
        {
            byte[] publicPart = _diffieHellanInstance.GetPublicKey();

            using (SHA256Managed sha = new SHA256Managed())
            {
                byte[] proofPart;

                if (_isSigner)
                {
                    // Sign the hash with the private key
                    proofPart = _rsa.SignData(publicPart, sha);
                }
                else
                {
                    // Encrypt the public part with the opposite public
                    proofPart = _rsa.Encrypt(sha.ComputeHash(publicPart), false);
                }

                // Final has two lengths appended
                byte[] final = new byte[(sizeof(ushort) * 2) + publicPart.Length + proofPart.Length];

                // Write lengths to final
                for (byte i = 0; i < sizeof(ushort); i++) final[i] = ((byte)(publicPart.Length >> (i * 8)));
                for (byte i = 0; i < sizeof(ushort); i++) final[i + sizeof(ushort)] = ((byte)(proofPart.Length >> (i * 8)));

                // Copy parts
                Buffer.BlockCopy(publicPart, 0, final, (sizeof(ushort) * 2), publicPart.Length);
                Buffer.BlockCopy(proofPart, 0, final, (sizeof(ushort) * 2) + publicPart.Length, proofPart.Length);

                return final;
            }
        }

        public byte[] GetVerifiedSharedPart(byte[] securePart)
        {
            if (securePart.Length < 4)
            {
                throw new ArgumentException("Signed part was too short");
            }

            // Read lengths
            ushort publicLength = (ushort)(((ushort)securePart[0]) | ((ushort)securePart[1] << 8));
            ushort proofLength = (ushort)(((ushort)securePart[2]) | ((ushort)securePart[3] << 8));

            if (securePart.Length != publicLength + proofLength + (sizeof(ushort) * 2))
            {
                throw new CryptographicException("Part lengths did not match");
            }

            // Alloc parts
            byte[] publicPart = new byte[publicLength];
            byte[] proofPart = new byte[proofLength];

            // Copy parts
            Buffer.BlockCopy(securePart, sizeof(ushort) * 2, publicPart, 0, publicLength);
            Buffer.BlockCopy(securePart, sizeof(ushort) * 2 + publicLength, proofPart, 0, proofLength);

            if (_isSigner)
            {
                using (SHA256Managed sha = new SHA256Managed())
                {
                    byte[] claimedHash = _rsa.Decrypt(proofPart, false);
                    byte[] realHash = sha.ComputeHash(publicPart);

                    // Prevent timing attacks by using constant time
                    if (ComparisonUtils.ConstTimeArrayEqual(claimedHash, realHash))
                    {
                        return _diffieHellanInstance.GetSharedSecretRaw(publicPart);
                    }
                    else
                    {
                        throw new CryptographicException("Hash did not match the signed hash");
                    }
                }
            }
            else
            {
                using (SHA256Managed sha = new SHA256Managed())
                {
                    if (_rsa.VerifyData(publicPart, sha, proofPart))
                    {
                        return _diffieHellanInstance.GetSharedSecretRaw(publicPart);
                    }
                    else
                    {
                        throw new CryptographicException("Signature was invalid");
                    }
                }
            }
        }
    }
}
