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