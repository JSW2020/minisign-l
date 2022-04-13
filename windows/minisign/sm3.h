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

	unsigned int rotate_left(unsigned int a, unsigned int k);//ѭ������
	unsigned int T(int i);//�����滻
	unsigned int GG(unsigned int x, unsigned int y, unsigned int z, unsigned int i);//��������
	unsigned int FF(unsigned int x, unsigned int y, unsigned int z, unsigned int i);//��������
	void SM3_Init(SM3_H *smh);//iv��ʼ��
	void SM3_Block(SM3_H *smh);//����ѹ��
	void SM3_Cal(SM3_H *smh, const unsigned char *msg, size_t len, unsigned char *md);//����
	unsigned char *sm3(const unsigned char *d, size_t len, unsigned char *md);
	/*
	d:  data
	len:  byte length
	md: 32 bytes digest
	*/

#ifdef __cplusplus
}
#endif
//�������һ��cpp�Ĵ��룬��ô����extern "C"{��}�������еĴ��롣
//__cplusplus��cpp���Զ����һ����


#define P0(X)  (X ^  rotate_left(X,9) ^  rotate_left(X,17))//�û�����
#define P1(X)  (X ^  rotate_left(X,15) ^  rotate_left(X,23))

//�ֵĴ洢Ϊ���(big-endian)��ʽ




#endif