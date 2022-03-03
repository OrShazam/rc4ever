/**
 * @file encrypt.h
 * @brief Encrypt data.
 *
 * @author Chen Zhenshuo (chenzs108@outlook.com)
 * @version 1.0
 * @date 2020-01-13
 * @par GitHub
 * https://github.com/czs108
 */
#pragma once 
#include <time.h>
#include <stdlib.h>
typedef unsigned char byte;

void RC4Encrypt(byte* key, int keylen, byte* data, int datalen);

byte* GenerateRandomKey(size_t keylen);