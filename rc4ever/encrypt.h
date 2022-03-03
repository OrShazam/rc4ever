#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <time.h>
#include <stdlib.h>
typedef unsigned char byte;

void RC4Encrypt(byte* key, int keylen, byte* data, int datalen);
 
void RC4Decrypt(byte* key, int keylen, byte* data, int datalen);

void RC4InitState(byte* S, byte* key, int keylen);

byte RC4GenerateRandomByte(byte* S, int* i, int* j);

byte* GenerateRandomKey(size_t keylen);

#endif