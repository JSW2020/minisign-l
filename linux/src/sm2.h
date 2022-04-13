#ifndef _SM2_H_
#define _SM2_H_
//条件指示符#ifndef 的最主要目的是防止头文件的重复包含和编译。

#include"sm3.h"
#include<miracl.h>

//#define SM2_DEBUG   TRUE
#define SM2_DEBUG   FALSE

#define SM2_PAD_ZERO TRUE
//#define SM2_PAD_ZERO FALSE


typedef struct ECC
{
	char *p;  //素数
	char *a;
	char *b;
	char *n;  //阶
	char *Gx;
	char *Gy;
};//椭圆曲线的参数

// 
//KDF是密钥派生函数

#ifdef __cplusplus
extern "C" {
#endif

	int sm3_e(unsigned char *userid, int userid_len, unsigned char *pkx, int pkx_len, unsigned char *pky, int pky_len, unsigned char *msg, size_t msg_len, unsigned char *e);
	/*
	功能：根据用户ID及公钥，求用于签名或验签的消息HASH值
	[输入] userid： 用户ID
	[输入] userid_len： userid的字节数
	[输入] pkx： 公钥的X坐标
	[输入] pkx_len: pkx的字节数
	[输入] pky： 公钥的Y坐标
	[输入] pky_len: pky的字节数
	[输入] msg：要签名的消息
	[输入] msg_len： msg的字节数
	[输出] e：32字节，用于签名或验签
	返回值：
			－1：内存不足
			  0：成功
	*/

	void sm2_keygen(unsigned char *pkx, int *pkxlen, unsigned char *pky, int *pkylen, unsigned char *sk, int *sklen);
	/*
	功能：生成SM2公私钥对
	[输出] pkx：   公钥的X坐标，不足32字节在前面加0x00
	[输出] pkxlen: pkx的字节数，32
	[输出] pky：   公钥的X坐标，不足32字节在前面加0x00
	[输出] pkylen: pky的字节数，32
	[输出] sk：私钥，不足32字节在前面加0x00
	[输出] sklen： sk的字节数，32
	*/

	void sm2_recreate_pk(unsigned char *sk, int sklen, unsigned char *pkx, unsigned char *pky);
	/*
	功能：由私钥重新生成公钥
	[输入]sk：私钥，不足32字节在前面加0x00
	[输入]sklen： sk的字节数
	[输出]pkx:公钥的X坐标，不足32字节在前面加0x00
	[输出]pky:公钥的X坐标，不足32字节在前面加0x00
	
	*/

	void sm2_sign(unsigned char *hash, int hashlen, unsigned char *sk, int sklen, unsigned char *cr, int *rlen, unsigned char *cs, int *slen);
	/*
	功能：SM2签名
	[输入] hash：    sm3_e()的结果
	[输入] hashlen： hash的字节数，应为32
	[输入] sk： 私钥
	[输入] sklen： sklen的字节数

	[输出] cr：  签名结果的第一部分，不足32字节在前面加0x00。
	[输出] rlen：cr的字节数，32
	[输出] cs：  签名结果的第二部分，不足32字节在前面加0x00。
	[输出] slen：cs的字节数，32
	*/

	int  sm2_verify(unsigned char *hash, int hashlen, unsigned char  *cr, int rlen, unsigned char *cs, int slen, unsigned char *pkx, int pkxlen, unsigned char *pky, int pkylen);
	/*
	功能：验证SM2签名
	[输入] hash：    sm3_e()的结果
	[输入] hashlen： hash的字节数，应为32
	[输入] cr：  签名结果的第一部分
	[输入] rlen：cr的字节数
	[输入] cs：  签名结果的第二部分。
	[输入] slen：cs的字节数
	[输入] pkx：   公钥的X坐标
	[输入] pkxlen: pkx的字节数，不超过32字节
	[输入] pky：   公钥的Y坐标
	[输入] pkylen: pky的字节数，不超过32字节
	返回值：
			0：验证失败
			1：验证通过
	*/

	int  A_encrypt(char *msg, int msglen, char *pkx, int pkxlen, char *pky, int pkylen, char *outmsg);
	/*
	功能：用SM2公钥加密数据。加密结果比输入数据多96字节！
	[输入] msg     要加密的数据
	[输入] msglen：msg的字节数
	[输入] pkx：    公钥的X坐标
	[输入] pkxlen:  pkx的字节数，不超过32字节
	[输入] pky：    公钥的Y坐标
	[输入] pkylen:  pky的字节数，不超过32字节
	[输出] outmsg: 加密结果，比输入数据多96字节！，C1（64字节）和C3（32字节）保留前导0x00
	返回值：
			-1：        加密失败
			msglen+96： 加密成功
	*/

	int  B_decrypt(char *msg, int msglen, char *sk, int sklen, char *outmsg);
	/*
	功能：用SM2私钥解密数据。解密结果比输入数据少96字节！
	[输入] msg     要解密的数据，是sm2_encrypt()加密的结果，不少于96字节。
	[输入] msglen：msg的字节数
	[输入] sk： 私钥
	[输入] sklen： sklen的字节数
	[输出] outmsg: 解密结果，比输入数据少96字节！
	返回值：
			-1：        解密失败
			msglen-96： 解密成功
	*/

#ifdef __cplusplus
}
#endif


#endif