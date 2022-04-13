#ifndef _SM3_H_
#define _SM3_H_

#include<stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DEBUG_SM3 0

#define  SM3_DIGEST_LENGTH  32


	typedef struct SM3_CHA //Cryptographic Hash Algorithm
	{
		unsigned int h[8];
		unsigned char data[64];
	} SM3_H;

	unsigned int rotate_left(unsigned int a, unsigned int k);//循环左移
	unsigned int T(int i);//常量替换
	unsigned int GG(unsigned int x, unsigned int y, unsigned int z, unsigned int i);//布尔函数
	unsigned int FF(unsigned int x, unsigned int y, unsigned int z, unsigned int i);//布尔函数
	void SM3_Init(SM3_H *smh);//iv初始化
	void SM3_Block(SM3_H *smh);//迭代压缩
	void SM3_Cal(SM3_H *smh, const unsigned char *msg, size_t len, unsigned char *md);//计算
	unsigned char *sm3(const unsigned char *d, size_t len, unsigned char *md);
	/*
	d:  data
	len:  byte length
	md: 32 bytes digest
	*/

#ifdef __cplusplus
}
#endif
//如果这是一段cpp的代码，那么加入extern "C"{和}处理其中的代码。
//__cplusplus是cpp中自定义的一个宏


#define P0(X)  (X ^  rotate_left(X,9) ^  rotate_left(X,17))//置换函数
#define P1(X)  (X ^  rotate_left(X,15) ^  rotate_left(X,23))

//字的存储为大端(big-endian)格式




#endif