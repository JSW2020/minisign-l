#ifndef _SM2_H_
#define _SM2_H_
//����ָʾ��#ifndef ������ҪĿ���Ƿ�ֹͷ�ļ����ظ������ͱ��롣

#include"sm3.h"
#include<miracl.h>

//#define SM2_DEBUG   TRUE
#define SM2_DEBUG   FALSE

#define SM2_PAD_ZERO TRUE
//#define SM2_PAD_ZERO FALSE


typedef struct ECC
{
	char *p;  //����
	char *a;
	char *b;
	char *n;  //��
	char *Gx;
	char *Gy;
};//��Բ���ߵĲ���

// 
//KDF����Կ��������

#ifdef __cplusplus
extern "C" {
#endif

	int sm3_e(unsigned char *userid, int userid_len, unsigned char *pkx, int pkx_len, unsigned char *pky, int pky_len, unsigned char *msg, size_t msg_len, unsigned char *e);
	/*
	���ܣ������û�ID����Կ��������ǩ������ǩ����ϢHASHֵ
	[����] userid�� �û�ID
	[����] userid_len�� userid���ֽ���
	[����] pkx�� ��Կ��X����
	[����] pkx_len: pkx���ֽ���
	[����] pky�� ��Կ��Y����
	[����] pky_len: pky���ֽ���
	[����] msg��Ҫǩ������Ϣ
	[����] msg_len�� msg���ֽ���
	[���] e��32�ֽڣ�����ǩ������ǩ
	����ֵ��
			��1���ڴ治��
			  0���ɹ�
	*/

	void sm2_keygen(unsigned char *pkx, int *pkxlen, unsigned char *pky, int *pkylen, unsigned char *sk, int *sklen);
	/*
	���ܣ�����SM2��˽Կ��
	[���] pkx��   ��Կ��X���꣬����32�ֽ���ǰ���0x00
	[���] pkxlen: pkx���ֽ�����32
	[���] pky��   ��Կ��X���꣬����32�ֽ���ǰ���0x00
	[���] pkylen: pky���ֽ�����32
	[���] sk��˽Կ������32�ֽ���ǰ���0x00
	[���] sklen�� sk���ֽ�����32
	*/

	void sm2_recreate_pk(unsigned char *sk, int sklen, unsigned char *pkx, unsigned char *pky);
	/*
	���ܣ���˽Կ�������ɹ�Կ
	[����]sk��˽Կ������32�ֽ���ǰ���0x00
	[����]sklen�� sk���ֽ���
	[���]pkx:��Կ��X���꣬����32�ֽ���ǰ���0x00
	[���]pky:��Կ��X���꣬����32�ֽ���ǰ���0x00
	
	*/

	void sm2_sign(unsigned char *hash, int hashlen, unsigned char *sk, int sklen, unsigned char *cr, int *rlen, unsigned char *cs, int *slen);
	/*
	���ܣ�SM2ǩ��
	[����] hash��    sm3_e()�Ľ��
	[����] hashlen�� hash���ֽ�����ӦΪ32
	[����] sk�� ˽Կ
	[����] sklen�� sklen���ֽ���

	[���] cr��  ǩ������ĵ�һ���֣�����32�ֽ���ǰ���0x00��
	[���] rlen��cr���ֽ�����32
	[���] cs��  ǩ������ĵڶ����֣�����32�ֽ���ǰ���0x00��
	[���] slen��cs���ֽ�����32
	*/

	int  sm2_verify(unsigned char *hash, int hashlen, unsigned char  *cr, int rlen, unsigned char *cs, int slen, unsigned char *pkx, int pkxlen, unsigned char *pky, int pkylen);
	/*
	���ܣ���֤SM2ǩ��
	[����] hash��    sm3_e()�Ľ��
	[����] hashlen�� hash���ֽ�����ӦΪ32
	[����] cr��  ǩ������ĵ�һ����
	[����] rlen��cr���ֽ���
	[����] cs��  ǩ������ĵڶ����֡�
	[����] slen��cs���ֽ���
	[����] pkx��   ��Կ��X����
	[����] pkxlen: pkx���ֽ�����������32�ֽ�
	[����] pky��   ��Կ��Y����
	[����] pkylen: pky���ֽ�����������32�ֽ�
	����ֵ��
			0����֤ʧ��
			1����֤ͨ��
	*/

	int  A_encrypt(char *msg, int msglen, char *pkx, int pkxlen, char *pky, int pkylen, char *outmsg);
	/*
	���ܣ���SM2��Կ�������ݡ����ܽ�����������ݶ�96�ֽڣ�
	[����] msg     Ҫ���ܵ�����
	[����] msglen��msg���ֽ���
	[����] pkx��    ��Կ��X����
	[����] pkxlen:  pkx���ֽ�����������32�ֽ�
	[����] pky��    ��Կ��Y����
	[����] pkylen:  pky���ֽ�����������32�ֽ�
	[���] outmsg: ���ܽ�������������ݶ�96�ֽڣ���C1��64�ֽڣ���C3��32�ֽڣ�����ǰ��0x00
	����ֵ��
			-1��        ����ʧ��
			msglen+96�� ���ܳɹ�
	*/

	int  B_decrypt(char *msg, int msglen, char *sk, int sklen, char *outmsg);
	/*
	���ܣ���SM2˽Կ�������ݡ����ܽ��������������96�ֽڣ�
	[����] msg     Ҫ���ܵ����ݣ���sm2_encrypt()���ܵĽ����������96�ֽڡ�
	[����] msglen��msg���ֽ���
	[����] sk�� ˽Կ
	[����] sklen�� sklen���ֽ���
	[���] outmsg: ���ܽ����������������96�ֽڣ�
	����ֵ��
			-1��        ����ʧ��
			msglen-96�� ���ܳɹ�
	*/

#ifdef __cplusplus
}
#endif


#endif