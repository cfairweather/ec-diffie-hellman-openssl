//
//  sha512.c
//  openssl-dhe-example
//
//  Created by Cris Fairweather on 8/9/13.
//  Copyright (c) 2013 CFairweather. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "sha512.h"

unsigned char *hash_sha512(unsigned char *data){
    SHA512_CTX ctx;
    unsigned char *md=malloc(sizeof(unsigned char)*(SHA512_DIGEST_LENGTH+1));
    
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, data, strlen(data));
    SHA512_Final(md, &ctx);
    md[SHA512_DIGEST_LENGTH]='\0';
    
    return md;
}