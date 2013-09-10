//
//  edch.c
//  openssl-dhe-example
//
//  Created by Cris Fairweather on 8/9/13.
//  Copyright (c) 2013 CFairweather
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ecdhe.h"

EC_DHE * EC_DHE_new(int EC_NID){
    EC_DHE  *ec_dhe = (EC_DHE*)calloc(1, sizeof *ec_dhe);
    
    ec_dhe->EC_NID = EC_NID;
    
    return ec_dhe;
}

void EC_DHE_free(EC_DHE *ec_dhe){
    //Contexts
    if(ec_dhe->ctx_params != NULL){
        EVP_PKEY_CTX_free(ec_dhe->ctx_params);
    }
    if(ec_dhe->ctx_keygen != NULL){
        EVP_PKEY_CTX_free(ec_dhe->ctx_keygen);
    }
    if(ec_dhe->ctx_derive != NULL){
        EVP_PKEY_CTX_free(ec_dhe->ctx_derive);
    }
    
    //Keys
    if(ec_dhe->privkey != NULL){
        EVP_PKEY_free(ec_dhe->privkey);
    }
    if(ec_dhe->peerkey != NULL){
        EVP_PKEY_free(ec_dhe->peerkey);
    }
    if(ec_dhe->params != NULL){
        EVP_PKEY_free(ec_dhe->params);
    }
    
    //Strings
    if(ec_dhe->publicKey != NULL){
        ec_dhe->publicKey[0] = '\0';
        free(ec_dhe->publicKey);
    }
    if(ec_dhe->sharedSecret != NULL){
        ec_dhe->sharedSecret[0] = '\0';
        free(ec_dhe->sharedSecret);
    }
    
    //Itself
    free(ec_dhe);
}


char *EC_DHE_getPublicKey(EC_DHE *ec_dhe, int *publicKeyLength){
    
    /* Create the context for parameter generation */
	if(NULL == (ec_dhe->ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))){
        EC_DHE_handleErrors("Could not create EC_DHE contexts.");
        return NULL;
    }
    
	/* Initialise the parameter generation */
	if(1 != EVP_PKEY_paramgen_init(ec_dhe->ctx_params)){
        EC_DHE_handleErrors("Could not intialize parameter generation.");
        return NULL;
    }
    
	/* We're going to use the ANSI X9.62 Prime 256v1 curve */
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ec_dhe->ctx_params, ec_dhe->EC_NID)){
        EC_DHE_handleErrors("Likely unknown elliptical curve ID specified.");
        return NULL;
    }
    
	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(ec_dhe->ctx_params, &ec_dhe->params)){
        EC_DHE_handleErrors("Could not create parameter object parameters.");
        return NULL;
    }
    
	/* Create the context for the key generation */
	if(NULL == (ec_dhe->ctx_keygen = EVP_PKEY_CTX_new(ec_dhe->params, NULL))){
        EC_DHE_handleErrors("Could not create the context for the key generation");
        return NULL;
    }
    
	
	if(1 != EVP_PKEY_keygen_init(ec_dhe->ctx_keygen)){
        EC_DHE_handleErrors("Could not init context for key generation.");
        return NULL;
    }
    
	if (1 != EVP_PKEY_keygen(ec_dhe->ctx_keygen, &ec_dhe->privkey)){
        EC_DHE_handleErrors("Could not generate DHE keys in final step");
        return NULL;
    }
    
    //Private & Public key pair have been created
    //Now, create a writable public key that can be sent over the network to our peer
    
    //Create our method of I/O, in this case, memory IO
    BIO* bp = BIO_new(BIO_s_mem());
    //Create the public key.
    if (1!=  PEM_write_bio_PUBKEY(bp, ec_dhe->privkey)){
        EC_DHE_handleErrors("Could not write public key to memory");
        return NULL;
    }
    
    BUF_MEM *bptr;
    //Get public key and place it in BUF_MEM struct pointer
    BIO_get_mem_ptr(bp, &bptr);
    
    //BIO_set_close(bp, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    //We want to clear the memory since we're going to copy the data into our own public key pointer.
    
    //Allocate and copy into our own struct
    ec_dhe->publicKey = calloc(1, bptr->length);
    memcpy(ec_dhe->publicKey, bptr->data, bptr->length);
    
    (*publicKeyLength) = bptr->length;//Assign length
    //Free our memory writer and buffer
    BIO_free(bp);
    
    
    return ec_dhe->publicKey;
}



unsigned char *EC_DHE_deriveSecretKey(EC_DHE *ec_dhe, const char *peerPublicKey, int peerPublicKeyLength, int *sharedSecretLength){

    //We can reconstruct an EVP_PKEY on this side to represent the peer key by parsing their public key we received from them.
    
    //New memory buffer that we can allocate using OpenSSL's method
    BUF_MEM *bptr = BUF_MEM_new();
    BUF_MEM_grow(bptr, peerPublicKeyLength);
    //Create a new BIO method, again, memory
    BIO* bp = BIO_new(BIO_s_mem());
    
    memcpy(bptr->data, peerPublicKey, peerPublicKeyLength);
    
    BIO_set_mem_buf(bp, bptr, BIO_NOCLOSE);
    
    ec_dhe->peerkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    
    //Memory cleanup from read/copy operation
    BIO_free(bp);
    BUF_MEM_free(bptr);
    
    //Now, let's derive the shared secret
    
    size_t secret_len = 0;
    
    /* Create the context for the shared secret derivation */
	if(NULL == (ec_dhe->ctx_derive = EVP_PKEY_CTX_new(ec_dhe->privkey, NULL))){
        EC_DHE_handleErrors("Could not create the context for the shared secret derivation");
        return NULL;
    }
    
	/* Initialise */
	if(1 != EVP_PKEY_derive_init(ec_dhe->ctx_derive)){
        EC_DHE_handleErrors("Could not init derivation context");
        return NULL;
    }
    
	/* Provide the peer public key */
	if(1 != EVP_PKEY_derive_set_peer(ec_dhe->ctx_derive, ec_dhe->peerkey)){
        EC_DHE_handleErrors("Could not set the peer key into derivation context");
        return NULL;
    }
    
	/* Determine buffer length for shared secret */
	if(1 != EVP_PKEY_derive(ec_dhe->ctx_derive, NULL, &secret_len)){
        EC_DHE_handleErrors("Could not determine buffer length for shared secret");
        return NULL;
    }
    
	/* Create the buffer */
	if(NULL == (ec_dhe->sharedSecret = OPENSSL_malloc(secret_len))){
        EC_DHE_handleErrors("Could not create the sharedSecret buffer");
        return NULL;
    }
    
	/* Dervive the shared secret */
	if(1 != (EVP_PKEY_derive(ec_dhe->ctx_derive, ec_dhe->sharedSecret, &secret_len))){
        EC_DHE_handleErrors("Could not dervive the shared secret");
        return NULL;
    }
    
    (*sharedSecretLength) = (int)secret_len;
	/* Never use a derived secret directly. Typically it is passed
	 * through some hash function to produce a key */
	return ec_dhe->sharedSecret;
}

static void EC_DHE_handleErrors(const char* errorMessage){
    if (errorMessage != NULL) {
        printf("%s", errorMessage);
    }
}


