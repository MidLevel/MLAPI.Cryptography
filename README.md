# MLAPI.Cryptography
MLAPI.Cryptography is a Unity friendly crypto library to fill the missing features of Unity's Mono runtime framework.

Currently it offers a BigInt, ECDHE, ECDHE_RSA and EllipticCurve implementation. Note that MLAPI.Cryptography is **NOT** designed to be an extensive crypto library such as NaCL or replace the .NET Framework. It's simply there to fill the missing gaps in the Unity Engine. Behind the scenes, MLAPI.Cryptography will use as much of the avalible .NET surface as possible. An example of this is the ECDHE_RSA implementation which uses MLAPI.Cryptographys BigInt, EllipticCurve and DiffieHellman implementations while it uses .NET's RSA implementation.


### ECDHE Usage
```csharp
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
```

### ECDHERSA Usage
```csharp
// Key pairs
RSAParameters privateKey;
RSAParameters publicKey;

// Generate keys, you can use X509Certificate2 instead of raw RSA keys.
using (RSACryptoServiceProvider rsaGen = new RSACryptoServiceProvider(2048))
{
    privateKey = rsaGen.ExportParameters(true);
    publicKey = rsaGen.ExportParameters(false);
}

using (RSACryptoServiceProvider serverRSA = new RSACryptoServiceProvider())
using (RSACryptoServiceProvider clientRSA = new RSACryptoServiceProvider())
{
    serverRSA.ImportParameters(privateKey);
    clientRSA.ImportParameters(publicKey);

    // Both create their instances, constructor can take certificate instead or RSA key.
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
}
```
### Timing Side Channel Attack Prevention
```csharp
byte[] array1 = new byte[120];
byte[] array2 = new byte[120];
array[50] = 67;

// This comparison will take constant time, no matter where the diff is (if any).
bool equal = ComparisonUtils.ConstTimeArrayEqual(array1, array2);
```