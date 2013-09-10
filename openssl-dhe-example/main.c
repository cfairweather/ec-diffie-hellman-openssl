//
//  main.c
//  openssl-dhe-example
//
//  Created by Cris Fairweather on 8/9/13.
//  Copyright (c) 2013 CFairweather. All rights reserved.
//

#include <stdio.h>
#include "ecdhe.h"


int main(int argc, const char * argv[])
{
    
    printf("Diffie Hellman Key Generation!\n\n");
    int NIDs[] = {NID_X9_62_c2pnb163v1, NID_X9_62_c2pnb163v2, NID_X9_62_c2pnb163v3, NID_X9_62_c2pnb176v1,NID_X9_62_c2tnb191v1,  NID_X9_62_c2tnb191v2,
        NID_X9_62_c2tnb191v3, NID_X9_62_c2pnb208w1, NID_X9_62_c2tnb239v1, NID_X9_62_c2tnb239v2, NID_X9_62_c2tnb239v3, NID_X9_62_c2pnb272w1, NID_X9_62_c2pnb304w1, NID_X9_62_c2tnb359v1, NID_X9_62_c2pnb368w1, NID_X9_62_c2tnb431r1, NID_X9_62_prime256v1,
        NID_secp112r1, NID_secp112r2,NID_secp128r1, NID_secp128r2, NID_secp160k1, NID_secp160r1, NID_secp160r2, NID_secp192k1, NID_secp224k1,NID_secp224r1, NID_secp256k1, NID_secp384r1, NID_secp521r1, NID_sect113r1, NID_sect113r2, NID_sect131r1, NID_sect131r2, NID_sect163k1, NID_sect163r1, NID_sect163r2 , NID_sect193r1, NID_sect193r2, NID_sect233k1, NID_sect233r1, NID_sect239k1, NID_sect283k1, NID_sect283r1, NID_sect409k1, NID_sect409r1, NID_sect571k1, NID_sect571r1,
        NID_wap_wsg_idm_ecid_wtls1, NID_wap_wsg_idm_ecid_wtls3, NID_wap_wsg_idm_ecid_wtls4, NID_wap_wsg_idm_ecid_wtls5, NID_wap_wsg_idm_ecid_wtls7, NID_wap_wsg_idm_ecid_wtls8, NID_wap_wsg_idm_ecid_wtls9, NID_wap_wsg_idm_ecid_wtls10, NID_wap_wsg_idm_ecid_wtls11, NID_wap_wsg_idm_ecid_wtls12};
    
    for (int a=0; a<sizeof(NIDs)/sizeof(int); a++) {
        printf("\n\nTrying Curve with ID: %d\n", NIDs[a]);
        
        //Our chosen curve must be used by both sides in the exchange
        int EC_Curve_ID = NIDs[a];
        
        EC_DHE *ec_dhe = EC_DHE_new(EC_Curve_ID);
        int publicKeyLength = 0;
        char *publicKey = EC_DHE_getPublicKey(ec_dhe,&publicKeyLength);
        
        printf("\nMy Public Key: \n%s", publicKey);
        
        
        //Normally here, we would send our public key and receive our peer's public key.
        //For example's sake, let's just generate a new key using the same curve
        EC_DHE *ec_dhePeer = EC_DHE_new(EC_Curve_ID);
        int peerKeyLength = 0;
        char *peerKey = EC_DHE_getPublicKey(ec_dhePeer,&peerKeyLength);
        
        printf("\nPeer Public Key: \n%s", peerKey);
        
        
        //Now that we have the peer's public key, let's derive the shared secret on the original side
        int sharedSecretLength = 0;
        unsigned char *sharedSecret = EC_DHE_deriveSecretKey(ec_dhe, peerKey, peerKeyLength, &sharedSecretLength);
        
        printf("\nShared Secret: \n");
        for(int i=0;i<sharedSecretLength;i++)
            printf("%X",sharedSecret[i]);//Hex value
        printf("\n");
        
        
        //Frees all memory used by EC_DHE, including publicKey, peerKey, and sharedSecret
        EC_DHE_free(ec_dhe);
        EC_DHE_free(ec_dhePeer);
        
        
        //WARNING!!!
        //peerKey, publicKey, and sharedSecret are no longer accessible once freed by EC_DHE_free
        //If you would like to keep them, make a copy
        
    }
    return 0;
}