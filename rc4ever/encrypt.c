
#include "encrypt.h"



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


void RC4Decrypt(byte* key, int keylen, byte* data, int datalen){
	return RC4Encrypt(key, keylen, data, datalen);
}

byte* GenerateRandomKey(size_t keylen){
	byte* buffer = malloc(keylen);
	srand(time(NULL));
	for (int i = 0; i < keylen; i++){
		buffer[i] = rand() % 256;
	}
	return buffer;
}