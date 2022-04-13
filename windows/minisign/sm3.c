#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "sm3.h"

unsigned int check_cpu()
{
	union {
		int i;
		char c;
	} uni;//共用体union
	uni.i = 1;
	return (uni.c == 1);
}

unsigned int rotate_left(unsigned int a, unsigned int k)
{
	k = k % 32;
	return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k));//
}

unsigned int T(int i)
{
	if (i >= 0 && i <= 15)
	{
		return 0x79cc4519;
	}
	if (i >= 16 && i <= 63)
	{
		return 0x7a879d8a;
	}
	else return 0;
}

unsigned int FF(unsigned int x, unsigned int y, unsigned int z, unsigned int i)
{
	if (i >= 0 && i <= 15)
	{
		return x ^ y ^ z;
	}
	if (i >= 16 && i <= 63)
	{
		return (x & y) | (x & z) | (y & z);
	}
	else return 0;
}

unsigned int GG(unsigned int x, unsigned int y, unsigned int z, unsigned int i)
{
	if (i >= 0 && i <= 15)
	{
		return x ^ y ^ z;
	}
	if (i >= 16 && i <= 63)
	{
		return (x & y) | ((~x) & z);
	}
	else return 0;
}

//反转四字节整型字节序
//大端模式

unsigned int *ReverseWord(unsigned int *word)
{
	unsigned char *byte, temp;

	byte = (unsigned char *)word;
	temp = byte[0];
	byte[0] = byte[3];
	byte[3] = temp;

	temp = byte[1];
	byte[1] = byte[2];
	byte[2] = temp;
	return word;
}

unsigned long long *ReverseWord1(unsigned long long *word)
{
	unsigned char *byte, temp;

	byte = (unsigned char *)word;
	temp = byte[0];
	byte[0] = byte[7];
	byte[7] = temp;

	temp = byte[1];
	byte[1] = byte[6];
	byte[6] = temp;

	temp = byte[2];
	byte[2] = byte[5];
	byte[5] = temp;

	temp = byte[3];
	byte[3] = byte[4];
	byte[4] = temp;
	return word;
}


void SM3_Init(SM3_H *smh)//IV=7380166f 4914b2b9 1724422d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e
{
	smh->h[0] = 0x7380166f;
	smh->h[1] = 0x4914b2b9;
	smh->h[2] = 0x172442d7;
	smh->h[3] = 0xda8a0600;
	smh->h[4] = 0xa96f30bc;
	smh->h[5] = 0x163138aa;
	smh->h[6] = 0xe38dee4d;
	smh->h[7] = 0xb0fb0e4e;
}

void SM3_Block(SM3_H *smh)
{
	int j;
	unsigned int t;
	unsigned int ss1, ss2, tt1, tt2;
	unsigned int a, b, c, d, e, f, g, h;
	unsigned int w[68], w_[64];

	//5.4.2 扩展消息
	for (j = 0; j < 16; j++)
	{
		//w[j] = smh->data[j * 4 + 0] << 24 | smh->data[j * 4 + 1] << 16 | smh->data[j * 4 + 2] << 8 | smh->data[j * 4 + 3];
		w[j] = *(unsigned int *)(smh->data + j * 4);
		
		if (check_cpu() == 1)//little-endian
		{
			ReverseWord(w + j);
		}
	}

	for (j = 16; j < 68; j++)
	{
		t = w[j - 16] ^ w[j - 9] ^ rotate_left(w[j - 3], 15);
		w[j] = P1(t) ^ rotate_left(w[j - 13], 7) ^ w[j - 6];
	}

	for (j = 0; j < 64; j++)
	{
		w_[j] = w[j] ^ w[j + 4];
	}
#if DEBUG_SM3
	printf("扩展后的消息 W0-67:\n");
	for (j = 0; j < 68; j++)
	{
		printf("%08x ", w[j]);
		if (((j + 1) % 8) == 0) printf("\n");
	}
	printf("\n");


	printf("扩展后的消息 W'0-63:\n");
	for (j = 0; j < 64; j++)
	{
		printf("%08x ", w_[j]);
		if (((j + 1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

	//5.3.3压缩函数
	a = smh->h[0];
	b = smh->h[1];
	c = smh->h[2];
	d = smh->h[3];
	e = smh->h[4];
	f = smh->h[5];
	g = smh->h[6];
	h = smh->h[7];
#if DEBUG_SM3
	printf("迭代压缩中间值:\n");
	printf("j     A       B        C         D         E        F        G       H\n");
	printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n", a, b, c, d, e, f, g, h);
#endif

	for (j = 0; j < 64; j++)
	{
		ss1 = rotate_left(rotate_left(a, 12) + e + rotate_left(T(j), j), 7);
		ss2 = ss1 ^ rotate_left(a, 12);
		tt1 = FF(a, b, c, j) + d + ss2 + w_[j];
		tt2 = GG(e, f, g, j) + h + ss1 + w[j];

		d = c;
		c = rotate_left(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = rotate_left(f, 19);
		f = e;
		e = P0(tt2);
#if DEBUG_SM3
		printf(" %d %08x %08x %08x %08x %08x %08x %08x %08x\n", j, a, b, c, d, e, f, g, h);
#endif
	}


	smh->h[0] ^= a;
	smh->h[1] ^= b;
	smh->h[2] ^= c;
	smh->h[3] ^= d;
	smh->h[4] ^= e;
	smh->h[5] ^= f;
	smh->h[6] ^= g;
	smh->h[7] ^= h;

}

void SM3_Cal(SM3_H *smh, const unsigned char *msg, size_t len, unsigned char *md)
{
	unsigned int i, remainder;
	size_t bitLen;
	/* 对前面的消息分组进行处理 */
	for (i = 0; i < len / 64; i++)  //i是B(i)分组数目（512bits），只有一组则不处理，因为0< 0不成立
	{
		memcpy(smh->data, msg + i * 64, 64);
		SM3_Block(smh);
	}
	/* 填充消息分组，并处理 */
	bitLen = len * 8;  //消息的比特长度，用于待会的填充
	remainder = len % 64;

	
	if (check_cpu() == 1)//little-endian
	{
		ReverseWord1(&bitLen);//big-endian
	}

	memset(&smh->data[remainder], 0, 64 - remainder);
	memcpy(smh->data, msg + i * 64, remainder);
	smh->data[remainder] = 0x80;//将bit1填充至消息末尾，再添加0

	if (remainder <= 55)
	{
		memset(smh->data + remainder + 1, 0, 64 - remainder - 1 - 8);
		memcpy(smh->data + 64 - 8, &bitLen, 8); //最后八字节存放信息长度
		SM3_Block(smh);
	}
	else
	{
		memset(smh->data + remainder + 1, 0, 64 - remainder - 1);//本组余下的全填零
		SM3_Block(smh);
		memset(smh->data, 0, 64);
		memcpy(smh->data + 64 - 8, &bitLen, 8);//最后八字节存放信息长度
		SM3_Block(smh);
	}
	if (check_cpu() == 1)//little-endian
	{
		for (i = 0; i < 8; i++)
		{
			ReverseWord(smh->h + i);//big-endian
		}//
	}

	memcpy(md, smh->h, SM3_DIGEST_LENGTH);

}


unsigned char *sm3(const unsigned char *d, size_t len, unsigned char *dig)
{
	SM3_H smh;

	SM3_Init(&smh);
	SM3_Cal(&smh, d, len, dig);
	memset(&smh, 0, sizeof(&smh));

	return(dig);
}
