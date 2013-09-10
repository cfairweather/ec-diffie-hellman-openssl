//
//  sha512.h
//  openssl-dhe-example
//
//  Created by Cris Fairweather on 8/9/13.
//  Copyright (c) 2013 CFairweather. All rights reserved.
//


#include <openssl/sha.h>

#ifndef __openssl_dhe_example__sha512__
#define __openssl_dhe_example__sha512__
unsigned char *hash_sha512(unsigned char *data);

#endif /* defined(__openssl_dhe_example__sha512__) */
