# MLAPI.Cryptography
MLAPI.Cryptography is a Unity friendly crypto library to fill the missing features of Unity's Mono runtime framework.

Currently it offers a BigInt implementation, a ECDHE implementation and a pure EllipticCurve implementation.


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