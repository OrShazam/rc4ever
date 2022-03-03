/**
 * @file encrypt.c
 * @brief Encrypt data.
 *
 * @author Chen Zhenshuo (chenzs108@outlook.com)
 * @version 1.0
 * @date 2020-01-13
 * @par GitHub
 * https://github.com/czs108
 */

#include "encrypt.h"

void RC4InitState(byte* S, byte* key, int keylen);

byte RC4GenerateRandomByte(byte* S, int* i, int* j);



void RC4Encrypt(byte* key, int keylen, byte* data, int datalen){
	byte S[256];
	RC4InitState(&S, key, keylen);
	int i = 0; int j = 0;
	for (int k = 0; k < datalen; k++){
		data[k] = data[k] ^ RC4GenerateRandomByte(&S, &i, &j);
	}
}

void RC4InitState(byte* S, byte* key, int keylen){
	int i;
	for (i = 0; i < 256; i++){
		S[i] = (byte)i;
	}
	int j = 0;
	byte temp;
	for (i = 0; i < 256; i++){
		j = (j + S[i] + key[i % keylen]) % 256;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
	}
	
}
byte RC4GenerateRandomByte(byte* S, int* i, int* j){
	byte temp;
	*i = (*i + 1) % 256;
	*j = (*j + S[*i]) % 256;
	temp = S[*i];
	S[*i] = S[*j];
	S[*j] = temp;
	return (byte)(S[( S[*i] + S[*j] ) % 256]);
}

