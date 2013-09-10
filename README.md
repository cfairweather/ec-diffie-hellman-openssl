#Elliptic Curve Diffie Hellman Merkle
### Wrapper for C

* EC_DHE is a well documented C wrapper for OpenSSL's implementation of EC Diffie Hellman Key Exchange. 
* Diffie Hellman is designed to give two clients the ability to negotiate a secure encryption key.
* Elliptic Curve DH simplifies usage and increases crypto strength by using named curves.

How To
--
Take a look at the main.c file to see an example of usage.
The quick and dirty is as follows:

    int myChosenEllipticCurveID = NID_X9_62_prime256v1;
    //Create a pointer to the wrapper
    EC_DHE *myEcdhePointer = EC_DHE_new(myChosenEllipticCurveID);
    //Get your public key
    //EC_DHE_getPublicKey()
    //Send it to peer
    
    //Receive Peer's public key
    //Derive Secret
    //EC_DHE_deriveSecretKey()
    
    //Clean up memory
    EC_DHE_free(myEcdhePointer);
  

--
Learn more about the principles of Diffie Hellman Merkle! https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange


"Elliptic Curve Diffie Hellman (ECDH) is an Elliptic Curve variant of the standard Diffie Hellman algorithm. See Elliptic Curve Cryptography for an overview of the basic concepts behind Elliptic Curve algorithms. ECDH is used for the purposes of key agreement."
http://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
