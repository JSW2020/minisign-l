#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <string.h>


#include "sm2.h"

//test data
unsigned char radom[] = { 0x6C,0xB2,0x8D,0x99,0x38,0x5C,0x17,0x5C,0x94,0xF9,0x4E,0x93,0x48,0x17,0x66,0x3F,0xC1,0x76,0xD9,0x25,0xDD,0x72,0xB7,0x27,0x26,0x0D,0xBA,0xAE,0x1F,0xB2,0xF9,0x6F };
unsigned char radom1[] = { 0x4C,0x62,0xEE,0xFD,0x6E,0xCF,0xC2,0xB9,0x5B,0x92,0xFD,0x6C,0x3D,0x95,0x75,0x14,0x8A,0xFA,0x17,0x42,0x55,0x46,0xD4,0x90,0x18,0xE5,0x38,0x8D,0x49,0xDD,0x7B,0x4F };


struct ECC bz = {
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
};//标准文件推荐参数


unsigned char sm2_par_dig[128] = {
0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
};

struct ECC bz1 = {
"8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
"8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
};

unsigned char sm2_par_dig1[128] = {
0x78,0x79,0x68,0xB4,0xFA,0x32,0xC3,0xFD,0x24,0x17,0x84,0x2E,0x73,0xBB,0xFE,0xFF,
0x2F,0x3C,0x84,0x8B,0x68,0x31,0xD7,0xE0,0xEC,0x65,0x22,0x8B,0x39,0x37,0xE4,0x98,//a
0x63,0xE4,0xC6,0xD3,0xB2,0x3B,0x0C,0x84,0x9C,0xF8,0x42,0x41,0x48,0x4B,0xFE,0x48,
0xF6,0x1D,0x59,0xA5,0xB1,0x6B,0xA0,0x6E,0x6E,0x12,0xD1,0xDA,0x27,0xC5,0x24,0x9A,//b
0x42,0x1D,0xEB,0xD6,0x1B,0x62,0xEA,0xB6,0x74,0x64,0x34,0xEB,0xC3,0xCC,0x31,0x5E,
0x32,0x22,0x0B,0x3B,0xAD,0xD5,0x0B,0xDC,0x4C,0x4E,0x6C,0x14,0x7F,0xED,0xD4,0x3D,//x
0x06,0x80,0x51,0x2B,0xCB,0xB4,0x2C,0x07,0xD4,0x73,0x49,0xD2,0x15,0x3B,0x70,0xC4,
0xE5,0xD7,0xFD,0xFC,0xBF,0xA3,0x6E,0xA1,0xA8,0x58,0x41,0xB9,0xE4,0x6E,0x09,0xA2,//y
};


void PrintBuf(unsigned char *buf, int buflen) //每32项为一行输出buf
{
	int i;
	printf("\n");
	for (i = 0; i < buflen; i++) {
		if (i % 32 != 31)
			printf("%02x", buf[i]);
		else
			printf("%02x\n", buf[i]);
	}
	printf("\n");
	return;
}
#define SEED_CONST 0x1BD8C95A


int sm3_e(unsigned char *userid, int userid_len, unsigned char *pkx, int pkx_len, unsigned char *pky, int pky_len, unsigned char *msg, size_t msg_len, unsigned char *e)
{
	unsigned char *buf;
	int userid_bitlen;

	if ((pkx_len > 32) || (pky_len > 32))
		return -1;

	buf = malloc(2 + userid_len + 128 + 32 + 32);
	if (buf == NULL)
		return -1;

	userid_bitlen = userid_len << 3;
	buf[0] = (userid_bitlen >> 8) & 0xFF;
	buf[1] = userid_bitlen & 0xFF;//ENTL

	memcpy(buf + 2, userid, userid_len);
	memcpy(buf + 2 + userid_len, sm2_par_dig, 128);

	memset(buf + 2 + userid_len + 128, 0, 64);
	memcpy(buf + 2 + userid_len + 128 + 32 - pkx_len, pkx, 32);
	memcpy(buf + 2 + userid_len + 128 + 32 + 32 - pky_len, pky, 32);

	sm3(buf, 2 + userid_len + 128 + 32 + 32, e);//ZA=H256(ENTLA ∥ IDA ∥ a ∥ b ∥ xG ∥	yG ∥ xA ∥ yA)

	free(buf);

#if SM2_DEBUG
	printf("ZA: ");
	PrintBuf(e, 32);
#endif

	buf = malloc(msg_len + 32);
	if (buf == NULL)
		return -1;

	memcpy(buf, e, 32);
	memcpy(buf + 32, msg, msg_len);
	sm3(buf, 32 + msg_len, e);//E = H256(ZA||M)

	free(buf);

	return 0;

}

//接收方B的私钥和公钥产生
void sm2_keygen(unsigned char *pkx, int *pkxlen, unsigned char *pky, int *pkylen, unsigned char *sk, int *sklen)
{
	struct ECC *ec = &bz;
	epoint *G, *P;//定义两个点
	big a, b, p, n, x, y, rk; //大数定义
	miracl *mip = mirsys(10000, 16);   //初始化大数系统（10000位的 16进制数）
	mip->IOBASE = 16;   //输入为16进制数

	p = mirvar(0);//保留适当数量的内存位置来初始化该变量
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	rk = mirvar(0);

	/*	//mip->IOBASE = 10;
		cinstr(a,"1247124623672752772");
		cinstr(n,"6033684446255071523");
		xgcd(a, n, b, b, b);
		printf("a=");
		cotnum(a, stdout);
		printf("b=");
		cotnum(b, stdout);
		printf("n=");
		cotnum(n, stdout);

		cinstr(x, "AF12398065BFE4C96DB723A");
		//mip->IOBASE = 10;
		cotnum(x, stdout);*/
	cinstr(p, ec->p);      //将大数字符串转换成大数 16进制byte-->大数
	cinstr(a, ec->a);
	cinstr(b, ec->b);
	cinstr(n, ec->n);
	cinstr(x, ec->Gx);
	cinstr(y, ec->Gy);

	ecurve_init(a, b, p, MR_PROJECTIVE);   //初始化椭圆曲线 y^2=x^3+ax+b （mod p）
	G = epoint_init();
	P = epoint_init();
	epoint_set(x, y, 0, G);    //基点G(x,y)

 //产生私钥
	irand(time(NULL) + SEED_CONST);   //初始化种子
	bigrand(n, rk);    //生成随机数rk<n
	ecurve_mult(rk, G, P);   //P=rk*G
	epoint_get(P, x, y);    //取P上的点（x，y）x和y即为公钥

#if SM2_DEBUG
	printf("pkx=");
	cotnum(x, stdout);
	printf("pky=");
	cotnum(y, stdout);
#endif	

#if SM2_PAD_ZERO

	*pkxlen = big_to_bytes(32, x, (char *)pkx, TRUE);    //公钥写入pkx，长度32
	*pkylen = big_to_bytes(32, y, (char *)pky, TRUE);
	*sklen = big_to_bytes(32, rk, (char *)sk, TRUE);    //私钥写入sk，长度32
	//big_to_bytes 将正数x转换为二进制八位字符串
#else

	*pkxlen = big_to_bytes(0, x, (char *)pkx, FALSE);    //公钥写入pkx，长度pkxlen
	*pkylen = big_to_bytes(0, y, (char *)pky, FALSE);
	*sklen = big_to_bytes(0, rk, (char *)sk, FALSE);
	//big_to_bytes 将正数x转换为二进制八位字符串
#endif

	mirkill(p);
	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(x);
	mirkill(y);
	mirkill(rk);
	epoint_free(G);
	epoint_free(P);
	mirexit();
}

void sm2_recreate_pk(unsigned char *sk, int sklen, unsigned char *pkx, unsigned char *pky)
{
	struct ECC *ec = &bz;
	epoint *G, *P;//定义两个点
	big a, b, p, n, x, y, rk; //大数定义
	miracl *mip = mirsys(10000, 16);   //初始化大数系统（10000位的 16进制数）
	mip->IOBASE = 16;   //输入为16进制数

	p = mirvar(0);//保留适当数量的内存位置来初始化该变量
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	rk = mirvar(0);

	cinstr(p, ec->p);      //将大数字符串转换成大数 16进制byte-->大数
	cinstr(a, ec->a);
	cinstr(b, ec->b);
	cinstr(n, ec->n);
	cinstr(x, ec->Gx);
	cinstr(y, ec->Gy);
	
	bytes_to_big(sklen, sk, rk);//字符串sk转换为大数rk

	ecurve_init(a, b, p, MR_PROJECTIVE);   //初始化椭圆曲线 y^2=x^3+ax+b （mod p）
	G = epoint_init();
	P = epoint_init();
	epoint_set(x, y, 0, G);    //基点G(x,y)
	ecurve_mult(rk, G, P);   //P=rk*G
	epoint_get(P, x, y);    //取P上的点（x，y）x和y即为公钥

	big_to_bytes(32, x, (char *)pkx, TRUE);    //公钥写入pkx，长度32
	big_to_bytes(32, y, (char *)pky, TRUE);
}



void sm2_sign(unsigned char *hash, int hashlen, unsigned char *sk, int sklen, unsigned char *cr, int *rlen, unsigned char *cs, int *slen)
{
	struct ECC *ec = &bz;
	epoint *G;
	big a, b, p, n, x, y, dA; //大数定义
	miracl *mip = mirsys(10000, 16);   //初始化大数系统
	mip->IOBASE = 16;   //输入为16进制数改为大数

	p = mirvar(0);//保留适当数量的内存位置来初始化该变量
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	dA = mirvar(0);

	big e, r, s, k;
	e = mirvar(0);//e存放hash结果 r,s签名结果 随机数k∈[1,n-1];
	r = mirvar(0);
	s = mirvar(0);
	k = mirvar(0);

	cinstr(p, ec->p);      //将大数字符串转换成大数 16进制byte-->大数
	cinstr(a, ec->a);
	cinstr(b, ec->b);
	cinstr(n, ec->n);
	cinstr(x, ec->Gx);
	cinstr(y, ec->Gy);

	ecurve_init(a, b, p, MR_PROJECTIVE);   //初始化椭圆曲线
	G = epoint_init();
	epoint_set(x, y, 0, G);    //基点G(x,y)


	bytes_to_big(sklen, sk, dA);//读取私钥
	bytes_to_big(hashlen, hash, e);//读取hash结果
	irand(time(NULL) + SEED_CONST);

	big tmp, s1, s2;
	tmp = mirvar(0);
	s1 = mirvar(0);
	s2 = mirvar(0);

sm2_sign_again:
#if SM2_DEBUG
	printf("n=");
	cotnum(n, stdout);
	printf("dA=");
	cotnum(dA, stdout);
	bytes_to_big(32, (char *)radom, k);
	printf("\nk=");
	cotnum(k, stdout);
#else
	do
	{
		bigrand(n, k);
	} while (k->len == 0);//生成随机数k<n
#endif

	ecurve_mult(k, G, G);//G=k*G=(r,r)
	epoint_get(G, r, r);//

#if SM2_DEBUG
	printf("x=");
	cotnum(r, stdout);
	printf("e=");
	cotnum(e, stdout);
	printf("\n");
#endif	
	add(e, r, r);
	divide(r, n, n);//r=(x1+e)%n


	if (r->len == 0)
		goto sm2_sign_again;

	add(r, k, tmp);

	if (mr_compare(tmp, n) == 0)//64位替换 compare
		goto sm2_sign_again;

	//s = ((1 + dA)^−1 *(k − r*dA)) modn
	incr(dA, 1, tmp);//tmp = dA+1
	//xgcd(tmp, n, tmp, tmp, s1);
	xgcd(tmp, n, s1, s1, s1);//s1 = tmp^-1 mod n

#if SM2_DEBUG
	printf("s1=");
	cotnum(s1, stdout);
#endif	

	multiply(r, dA, tmp);//tmp = r*dA
	divide(tmp, n, n);//tmp = tmp mod n
	//s2 = k - r*dA

	if (mr_compare(k, tmp) >= 0)
	{
		subtract(k, tmp, s2);//s2 = k -r*dA
	}
	else
	{
		subtract(n, tmp, tmp);//tmp>k tmp = n-tmp
		add(k, tmp, s2);//s2 = k + tmp=k + n -r*dA
	}
#if SM2_DEBUG
	printf("s2=");
	cotnum(s2, stdout);
#endif	

	mad(s2, s1, s2, n, n, s);
	//multiply(s1, s2, s);//tmp = s1*s2
	//divide(s, n, n);//s =(s1*s2)mod n

#if SM2_DEBUG
	printf("s=");
	cotnum(s, stdout);
	printf("\n");
#endif	

	if (s->len == 0)
		goto sm2_sign_again;

#if SM2_PAD_ZERO
	*rlen = big_to_bytes(32, r, (char *)cr, TRUE);
	*slen = big_to_bytes(32, s, (char *)cs, TRUE);
#else
	*rlen = big_to_bytes(0, r, (char *)cr, FALSE);
	*slen = big_to_bytes(0, s, (char *)cs, FALSE);
#endif	


	mirkill(e);
	mirkill(r);
	mirkill(s);
	mirkill(k);
	mirkill(p);
	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(x);
	mirkill(y);
	mirkill(dA);
	mirkill(tmp);
	mirkill(s1);
	mirkill(s2);
	epoint_free(G);
	mirexit();

}

int  sm2_verify(unsigned char *hash, int hashlen, unsigned char  *cr, int rlen, unsigned char *cs, int slen, unsigned char *pkx, int pkxlen, unsigned char *pky, int pkylen)
{
	struct ECC *ec = &bz;
	epoint *g, *pA;
	big a, b, p, n, x, y; //大数定义
	big e, r, s, x1, R, t;
	miracl *mip = mirsys(10000, 16);   //初始化大数系统
	mip->IOBASE = 16;   //输入为16进制数改为大数

	int ret = 0;
	p = mirvar(0);//保留适当数量的内存位置来初始化该变量
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	x1 = mirvar(0);

	e = mirvar(0);//e存放hash结果 r,s签名结果
	r = mirvar(0);
	s = mirvar(0);
	R = mirvar(0);
	t = mirvar(0);

	cinstr(p, ec->p);      //将大数字符串转换成大数 16进制byte-->大数
	cinstr(a, ec->a);
	cinstr(b, ec->b);
	cinstr(n, ec->n);
	cinstr(x, ec->Gx);
	cinstr(y, ec->Gy);

	ecurve_init(a, b, p, MR_PROJECTIVE);   //初始化椭圆曲线
	g = epoint_init();
	pA = epoint_init();
	epoint_set(x, y, 0, g);//初始化点G
	epoint_get(g, e, r);

	bytes_to_big(pkxlen, (char *)pkx, x);
	bytes_to_big(pkylen, (char *)pky, y);//公钥

#if SM2_DEBUG
	printf("pkx=");
	cotnum(x, stdout);
	printf("pky=");
	cotnum(y, stdout);
#endif	

	if (!epoint_set(x, y, 0, pA))
	{
		printf("Point error");
		goto exit_sm2_verify;
	}
	bytes_to_big(hashlen, (char *)hash, e);
	bytes_to_big(rlen, (char *)cr, r);
	bytes_to_big(slen, (char *)cs, s);

	if ((mr_compare(r, n) >= 0) || (r->len == 0) || (mr_compare(s, n) >= 0) || (s->len == 0))//B1,B2 r,s∈[1,n-1]
		goto exit_sm2_verify;


	add(s, r, t);

	divide(t, n, n);//B5 t = t mod n
	if (t->len == 0)
		goto exit_sm2_verify;

#if SM2_DEBUG
	printf("t=");
	cotnum(t, stdout);
#endif	

	ecurve_mult2(s, g, t, pA, g);//g = s'*g+t*pA
	epoint_get(g, x1, x1);
#if SM2_DEBUG
	printf("x1=");
	cotnum(x1, stdout);
#endif	


	add(x1, e, R);//R = x1+e
	divide(R, n, n);//R = R mod n
#if SM2_DEBUG
	printf("R=");
	cotnum(R, stdout);
#endif	

	if (mr_compare(R, r) == 0)
		ret = 1;

exit_sm2_verify:

	mirkill(r);
	mirkill(s);
	mirkill(R);
	mirkill(e);
	mirkill(a);
	mirkill(b);
	mirkill(p);
	mirkill(n);
	mirkill(x);
	mirkill(y);
	mirkill(x1);
	mirkill(t);
	epoint_free(g);
	epoint_free(pA);
	mirexit();

	return ret;
}

int kdf(unsigned char *zl, unsigned char *zr, int klen, unsigned char *kbuf) //密钥派生函数 //zl，zr为（x2，y2）
{

	unsigned char buf[70];
	unsigned char digest[32];
	unsigned int ct = 0x00000001;//初始化一个32比特构成的计数器
	int i, m, n;
	unsigned char *p = kbuf;

	memcpy(buf, zl, 32);                   //把x2，y2传入buf
	memcpy(buf + 32, zr, 32);

	m = klen / 32;
	n = klen % 32;

	for (i = 0; i < m; i++)       //buf 64-70
	{
		buf[64] = (ct >> 24) & 0xFF;   //ct前8位
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3(buf, 68, p);                       //sm3后结果放在p中
		p += 32;
		ct++;
	}

	if (n != 0)//有余
	{
		buf[64] = (ct >> 24) & 0xFF;
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3(buf, 68, digest);
	}

	memcpy(p, digest, n);//补充给p

	for (i = 0; i < klen; i++)
	{
		if (kbuf[i] != 0)      //kbuf中有i+1个0
			break;
	}

	if (i < klen)
		return 1;   //kbuf（t）中的bit全是0， kdf判断通过，执行下一步C2=M异或t
	else
		return 0;

}

int A_encrypt(char *msg, int msglen, char *pkx, int pkxlen, char *pky, int pkylen, char *outmsg)//pkx，pky公钥的x，y的坐标
{
	struct ECC *ec = &bz;
	big x2, y2, x1, y1, k;
	big a, b, p, n, x, y;
	epoint *g, *w, *pb, *c1, *kpb;
	int ret = -1;
	int i;
	unsigned char zl[32], zr[32];
	unsigned char *tmp;
	miracl *mip;
	tmp = malloc(msglen + 64);
	if (tmp == NULL)
		return -1;
	mip = mirsys(10000, 0);
	mip->IOBASE = 16;          //读入16进制数

	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	k = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);

	cinstr(p, ec->p);                    //大数字符串变为大数
	cinstr(a, ec->a);
	cinstr(b, ec->b);
	cinstr(n, ec->n);
	cinstr(x, ec->Gx);
	cinstr(y, ec->Gy);                                   //g=(x,y)

	ecurve_init(a, b, p, MR_PROJECTIVE);     //椭圆曲线方程初始化  y2 =x3 + Ax + B mod p
	g = epoint_init();                                   //点坐标初始化
	pb = epoint_init();
	kpb = epoint_init();
	c1 = epoint_init();
	w = epoint_init();
	epoint_set(x, y, 0, g);                             //点坐标设置  g=(x,y)，现在无值
	bytes_to_big(pkxlen, (char *)pkx, x);       //把公钥pkx和pky赋值给x，y
	bytes_to_big(pkylen, (char *)pky, y);
	epoint_set(x, y, 0, pb);                          //=(x1,y1)



	irand(time(NULL) + SEED_CONST);
sm2_encrypt_again:
	do
	{
		bigrand(n, k); //k<n
	} while (k->len == 0);

	ecurve_mult(k, g, c1);                 //  点乘c1=k*g(第三个=第一个*第二个)
	epoint_get(c1, x1, y1);            //从c1里面得到x1，y1
	big_to_bytes(32, x1, (char *)outmsg, TRUE);
	big_to_bytes(32, y1, (char *)outmsg + 32, TRUE);


	if (point_at_infinity(pb))          //如果s是无穷点，返回1，报错退出
		goto exit_sm2_encrypt;

	ecurve_mult(k, pb, kpb);    //kpb=K*pb
	epoint_get(kpb, x2, y2);   //从kpb得到x2，y2


	big_to_bytes(32, x2, (char *)zl, TRUE);   //把大数x2，y2变为字节放入zl，zr
	big_to_bytes(32, y2, (char *)zr, TRUE);

	//t=KDF(x2||y2,klen)
	if (kdf(zl, zr, msglen, outmsg + 64) == 0)  //如果kdf返回的值为0，从头开始重新计算
		goto sm2_encrypt_again;

	for (i = 0; i < msglen; i++)
	{
		outmsg[64 + i] ^= msg[i];
	}

	//tmp=x2 || M| |y2 相连
	memcpy(tmp, zl, 32);
	memcpy(tmp + 32, msg, msglen);
	memcpy(tmp + 32 + msglen, zr, 32);

	//C3=outmsg=hash(SM3)(tmp)
	sm3(tmp, 64 + msglen, &outmsg[64 + msglen]);
	ret = msglen + 64 + 32;

exit_sm2_encrypt:  //退出释放内存
	mirkill(x2);
	mirkill(y2);
	mirkill(x1);
	mirkill(y1);
	mirkill(k);
	mirkill(a);
	mirkill(b);
	mirkill(p);
	mirkill(n);
	mirkill(x);
	mirkill(y);
	epoint_free(g);   //释放点内存
	epoint_free(w);
	epoint_free(pb);
	epoint_free(kpb);
	mirexit();
	free(tmp);
	return ret;
}

//B收到密文后开始解密运算
int B_decrypt(char *msg, int msglen, char *sk, int sklen, char *outmsg)
{
	struct ECC *ec = &bz;
	big x2, y2, c, k;
	big a, b, p, n, x, y, rk, dB;
	epoint *g, *C1, *dBC1;
	unsigned char c3[32];
	unsigned char zl[32], zr[32];
	int i, ret = -1;
	unsigned char *tmp;
	miracl *mip;
	if (msglen < 96)
		return 0;
	msglen -= 96;
	tmp = malloc(msglen + 64);
	if (tmp == NULL)
		return 0;
	mip = mirsys(10000, 0);
	mip->IOBASE = 16;

	x2 = mirvar(0);
	y2 = mirvar(0);
	c = mirvar(0);
	k = mirvar(0);
	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	rk = mirvar(0);
	dB = mirvar(0);
	bytes_to_big(sklen, (char *)sk, dB);
	cinstr(p, ec->p);
	cinstr(a, ec->a);
	cinstr(b, ec->b);
	cinstr(n, ec->n);
	cinstr(x, ec->Gx);
	cinstr(y, ec->Gy);


	ecurve_init(a, b, p, MR_PROJECTIVE);  //初始化椭圆曲线 y2=x3+Ax+B （mod p）
	g = epoint_init();
	dBC1 = epoint_init();
	C1 = epoint_init();
	bytes_to_big(32, (char *)msg, x);    //从msg中分别取出32位放入x和y
	bytes_to_big(32, (char *)msg + 32, y);

	if (!epoint_set(x, y, 0, C1))     //初始化点C1=（x，y）点C1=（x，y）是否在椭圆曲线 上
		goto exit_sm2_decrypt;
	if (point_at_infinity(C1))     //如果s（test）是无穷远点，报错并退出
		goto exit_sm2_decrypt;

	ecurve_mult(dB, C1, dBC1);   //dBC1=dB*c1
	epoint_get(dBC1, x2, y2);    //从dBC1中读取x2，y2

	big_to_bytes(32, x2, (char *)zl, TRUE);
	big_to_bytes(32, y2, (char *)zr, TRUE);

	if (kdf(zl, zr, msglen, outmsg) == 0)  //判断：t=kdf不是全0，才继续
		goto exit_sm2_decrypt;
	for (i = 0; i < msglen; i++)     //M'(outmsg)=C2 ^ t(outmsg)
	{
		outmsg[i] ^= msg[i + 64];//密文从65位开始为c2
	}
	memcpy(tmp, zl, 32);
	memcpy(tmp + 32, outmsg, msglen);
	memcpy(tmp + 32 + msglen, zr, 32);
	sm3(tmp, 64 + msglen, c3);
	if (memcmp(c3, msg + 64 + msglen, 32) != 0)//判断u=c3则继续
		goto exit_sm2_decrypt;
	ret = msglen;

exit_sm2_decrypt:
	mirkill(x2);
	mirkill(y2);
	mirkill(c);
	mirkill(k);
	mirkill(p);
	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(x);
	mirkill(y);
	mirkill(rk);
	mirkill(dB);
	epoint_free(g);
	epoint_free(dBC1);
	mirexit();
	free(tmp);

	return ret;
}



