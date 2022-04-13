
#include "asprintf.h"

#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sm3.h"
#include "sm2.h"
#include <miracl.h>

#include <sodium.h>

#include "base64.h"
#include "get_line.h"
#include "helpers.h"
#include "minisign.h"


#ifndef crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN
# define crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN 32768U
# define crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN 16777216U
#endif

#ifndef VERIFY_ONLY
static const char *getopt_options = "GSVRHhc:fm:oP:p:qQs:t:vx:Mu:";
#else
static const char *getopt_options = "Vhm:oP:p:qQvx:";
#endif

static void usage(void) __attribute__((noreturn));

static void
usage(void)
{
    puts("Usage:\n"
#ifndef VERIFY_ONLY
         "minisign -G [-M] [-p pubkey] [-s seckey]\n"
         "minisign -S [-M] [-u userid] [-H] [-x sigfile] [-s seckey] [-c untrusted_comment] [-t trusted_comment] -m file [file ...]\n"
#endif
         "minisign -V [-M] [-x sigfile] [-p pubkeyfile | -P pubkey] [-o] [-q] -m file\n"
#ifndef VERIFY_ONLY
         "minisign -R -s seckey -p pubkeyfile\n"
#endif
         "\n"
#ifndef VERIFY_ONLY
         "-G                generate a new key pair\n"
         "-S                sign files\n"
#endif
         "-V                verify that a signature is valid for a given file\n"
         "-m <file>         file to sign/verify\n"
         "-o                combined with -V, output the file content after verification\n"
#ifndef VERIFY_ONLY
         "-H                combined with -S, pre-hash in order to sign large files\n"
#endif
         "-p <pubkeyfile>   public key file (default: ./minisign.pub | ./minisign2.pub)\n"
         "-P <pubkey>       public key, as a base64 string\n"
#ifndef VERIFY_ONLY
         "-s <seckey>       secret key file (default: ~/.minisign/minisign.key | minisign2.key)\n"
#endif
         "-x <sigfile>      signature file (default: <file>.minisig | <file>.minisig2)\n"
#ifndef VERIFY_ONLY
         "-c <comment>      add a one-line untrusted comment\n"
         "-t <comment>      add a one-line trusted comment\n"
#endif
         "-q                quiet mode, suppress output\n"
         "-Q                pretty quiet mode, only print the trusted comment\n"
#ifndef VERIFY_ONLY
         "-R                recreate a public key file from a secret key file\n"
#endif
         "-f                force. Combined with -G, overwrite a previous key pair\n"
         "-v                display version number\n"
		 "		SM2 MODE(with sm3_hashed)					\n"
		 "-M	            use the 'sm2' mode \n"
		 "-u	            add a userid for sm2(3)  \n"
        );
    exit(2);
}

void Print_Buf(unsigned char *buf, int buflen) //每32项为一行输出buf
{
	int i;
	printf("\n");
	for (i = 0; i < buflen; i++)
	{
		printf("%02x", buf[i]);
		if (((i + 1) % 4) == 0)
			printf(" ");
		if (((i + 1) % 32) == 0)
			printf("\n");
	}
	printf("\n");
	return;
}

static unsigned char *
message_load_hashed(size_t *message_len, const char *message_file)
{
    crypto_generichash_state  hs;
    unsigned char             buf[65536U];
    unsigned char            *message;
    FILE                     *fp;
    size_t                    n;

    if ((fp = fopen(message_file, "rb")) == NULL) {
        exit_err(message_file);
    }
    crypto_generichash_init(&hs, NULL, 0U, crypto_generichash_BYTES_MAX);
    while ((n = fread(buf, 1U, sizeof buf, fp)) > 0U) {
        crypto_generichash_update(&hs, buf, n);
    }
    if (!feof(fp)) {
        exit_err(message_file);
    }
    xfclose(fp);
    message = xmalloc(crypto_generichash_BYTES_MAX);
    crypto_generichash_final(&hs, message, crypto_generichash_BYTES_MAX);
    *message_len = crypto_generichash_BYTES_MAX;

    return message;
}

static unsigned char *
message_load(size_t *message_len, const char *message_file, int hashed)
{
    FILE          *fp;
    unsigned char *message;
    size_t         message_len_;

    if (hashed != 0) {
        return message_load_hashed(message_len, message_file);
    }
    if ((fp = fopen(message_file, "rb")) == NULL ||
        _fseeki64(fp, 0, SEEK_END) != 0 ||
        (message_len_ = _ftelli64(fp)) == (size_t) -1) {
        exit_err(message_file);
    }
    assert(hashed == 0);
	
    if (message_len_ > (size_t) 1L << 30) {
        exit_msg("Data has to be smaller than 1 GB. Or use the -H option.");
    }
    if ((uintmax_t) message_len_ > (uintmax_t) SIZE_MAX ||
        message_len_ < (size_t) 0) {
        abort();
    }
    message = xmalloc((*message_len = (size_t) message_len_));
    rewind(fp);
    if (*message_len > 0U &&
        fread(message, *message_len, (size_t) 1U, fp) != 1U) {
        exit_msg("Error while loading the message");
    }
    xfclose(fp);

    return message;
}

static int
output_file(const char *message_file)
{
    unsigned char  buf[65536U];
    FILE          *fp;
    size_t         n;

    if ((fp = fopen(message_file, "rb")) == NULL) {
        exit_err(message_file);
    }
    while ((n = fread(buf, 1U, sizeof buf, fp)) > 0U) {
        if (fwrite(buf, 1U, n, stdout) != n) {
            exit_err(message_file);
        }
    }
    if (!feof(fp) || fflush(stdout) != 0) {
        exit_err(message_file);
    }
    xfclose(fp);

    return 0;
}

static SigStruct *
sig_load(const char *sig_file, unsigned char global_sig[crypto_sign_BYTES],
         int *hashed, char trusted_comment[TRUSTEDCOMMENTMAXBYTES],
         size_t trusted_comment_maxlen)
{
    char       comment[COMMENTMAXBYTES];
    SigStruct *sig_struct;
    FILE      *fp;
    char      *global_sig_s;
    char      *sig_s;
    size_t     global_sig_len;
    size_t     global_sig_s_size;
    size_t     sig_s_size;
    size_t     sig_struct_len;

    if ((fp = fopen(sig_file, "r")) == NULL) {
        exit_err(sig_file);
    }
    if (fgets(comment, (int) sizeof comment, fp) == NULL) {
        exit_msg("Error while reading the signature file");
    }
    if (strncmp(comment, COMMENT_PREFIX, (sizeof COMMENT_PREFIX) - 1U) != 0) {
        exit_msg("Untrusted signature comment should start with "
                 "\"" COMMENT_PREFIX "\"");
    }
    sig_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *sig_struct) + 2U;
    sig_s = xmalloc(sig_s_size);
    if (fgets(sig_s, (int) sig_s_size, fp) == NULL) {
        exit_msg("Error while reading the signature file");
    }
    trim(sig_s);
    if (fgets(trusted_comment, (int) trusted_comment_maxlen, fp) == NULL) {
        exit_msg("Trusted comment not present");
    }
    if (strncmp(trusted_comment, TRUSTED_COMMENT_PREFIX,
                (sizeof TRUSTED_COMMENT_PREFIX) - 1U) != 0) {
        exit_msg("Trusted signature comment should start with "
                 "\"" TRUSTED_COMMENT_PREFIX "\"");
    }
    memmove(trusted_comment,
            trusted_comment + sizeof TRUSTED_COMMENT_PREFIX - 1U,
            strlen(trusted_comment + sizeof TRUSTED_COMMENT_PREFIX - 1U) + 1U);
    trim(trusted_comment);
    global_sig_s_size = B64_MAX_LEN_FROM_BIN_LEN(crypto_sign_BYTES) + 2U;
    global_sig_s = xmalloc(global_sig_s_size);
    if (fgets(global_sig_s, (int) global_sig_s_size, fp) == NULL) {
        exit_msg("Error while reading the signature file");
    }
    trim(global_sig_s);
    xfclose(fp);

    sig_struct = xmalloc(sizeof *sig_struct);
    if (b64_to_bin((unsigned char *) (void *) sig_struct, sig_s,
                   sizeof *sig_struct, strlen(sig_s),
                   &sig_struct_len) == NULL ||
        sig_struct_len != sizeof *sig_struct) {
        exit_msg("base64 conversion failed - was an actual signature given?");
    }
    free(sig_s);
    if (memcmp(sig_struct->sig_alg, SIGALG, sizeof sig_struct->sig_alg) == 0 ||
		memcmp(sig_struct->sig_alg, SIGALG1, sizeof sig_struct->sig_alg) == 0) {
		*hashed = 0;
    } else if (memcmp(sig_struct->sig_alg, SIGALG_HASHED,
                      sizeof sig_struct->sig_alg) == 0 || memcmp(sig_struct->sig_alg, SIGALG1_HASHED,
						  sizeof sig_struct->sig_alg) == 0) {
        *hashed = 1;
    } else {
        exit_msg("Unsupported signature algorithm");
    }
    if (b64_to_bin(global_sig, global_sig_s, crypto_sign_BYTES,
                   strlen(global_sig_s), &global_sig_len) == NULL ||
        global_sig_len != crypto_sign_BYTES) {
        exit_msg("base64 conversion failed - was an actual signature given?");
    }
    free(global_sig_s);

    return sig_struct;
}

static PubkeyStruct *
pubkey_load_string(const char *pubkey_s)
{
    PubkeyStruct *pubkey_struct;
    size_t        pubkey_struct_len;

    pubkey_struct = xsodium_malloc(sizeof *pubkey_struct);
    if (b64_to_bin((unsigned char *) (void *) pubkey_struct, pubkey_s,
                   sizeof *pubkey_struct, strlen(pubkey_s),
                   &pubkey_struct_len) == NULL ||
        pubkey_struct_len != sizeof *pubkey_struct) {
        exit_msg("base64 conversion failed - was an actual public key given?");
    }
    if (memcmp(pubkey_struct->sig_alg, SIGALG,
               sizeof pubkey_struct->sig_alg) != 0 && memcmp(pubkey_struct->sig_alg, SIGALG1,
				   sizeof pubkey_struct->sig_alg) != 0) {
        exit_msg("Unsupported signature algorithm");
    }
    return pubkey_struct;
}

static PubkeyStruct *
pubkey_load_file(const char *pk_file)
{
    char          pk_comment[COMMENTMAXBYTES];
    PubkeyStruct *pubkey_struct;
    FILE         *fp;
    char         *pubkey_s = NULL;
    size_t        pubkey_s_size;

    if ((fp = fopen(pk_file, "r")) == NULL) {
        exit_err(pk_file);
    }
    if (fgets(pk_comment, (int) sizeof pk_comment, fp) == NULL) {
        exit_msg("Error while loading the public key file");
    }
    pubkey_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *pubkey_struct) + 2U;
    pubkey_s = xmalloc(pubkey_s_size);
    if (fgets(pubkey_s, (int) pubkey_s_size, fp) == NULL) {
        exit_msg("Error while loading the public key file");
    }
    trim(pubkey_s);
    xfclose(fp);
    pubkey_struct = pubkey_load_string(pubkey_s);
    free(pubkey_s);

    return pubkey_struct;
}

static PubkeyStruct *
pubkey_load(const char *pk_file, const char *pubkey_s)
{
    if (pk_file != NULL && pubkey_s != NULL) {
        exit_msg("A public key cannot be provided both inline and as a file");
    }
    if (pubkey_s != NULL) {
        return pubkey_load_string(pubkey_s);
    } else if (pk_file != NULL) {
        return pubkey_load_file(pk_file);
    }
    exit_msg("A public key is required");
}

static void
seckey_chk(unsigned char chk[crypto_generichash_BYTES],
           const SeckeyStruct *seckey_struct)
{
    crypto_generichash_state hs;//Multi-part example with a key

    crypto_generichash_init(&hs, NULL, 0U, sizeof seckey_struct->keynum_sk.chk);
    crypto_generichash_update(&hs, seckey_struct->sig_alg,
                              sizeof seckey_struct->sig_alg);
    crypto_generichash_update(&hs, seckey_struct->keynum_sk.keynum,
                              sizeof seckey_struct->keynum_sk.keynum);
    crypto_generichash_update(&hs, seckey_struct->keynum_sk.sk,
                              sizeof seckey_struct->keynum_sk.sk);
    crypto_generichash_final(&hs, chk, sizeof seckey_struct->keynum_sk.chk);
}

#ifndef VERIFY_ONLY
static SeckeyStruct *
seckey_load(const char *sk_file)
{
    char           sk_comment[COMMENTMAXBYTES];
    unsigned char  chk[crypto_generichash_BYTES];
    SeckeyStruct  *seckey_struct;
    FILE          *fp;
    char          *pwd = xsodium_malloc(PASSWORDMAXBYTES);
    char          *seckey_s;
    unsigned char *stream;
    size_t         seckey_s_size;
    size_t         seckey_struct_len;

    if ((fp = fopen(sk_file, "r")) == NULL) {
        exit_err(sk_file);
    }
    if (fgets(sk_comment, (int) sizeof sk_comment, fp) == NULL) {
        exit_msg("Error while loading the secret key file");
    }
    sodium_memzero(sk_comment, sizeof sk_comment);
    seckey_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *seckey_struct) + 2U;
    seckey_s = xsodium_malloc(seckey_s_size);
    seckey_struct = xsodium_malloc(sizeof *seckey_struct);

    if (fgets(seckey_s, (int) seckey_s_size, fp) == NULL) {
        exit_msg("Error while loading the secret key file");
    }
    trim(seckey_s);
    xfclose(fp);
    if (b64_to_bin((unsigned char *) (void *) seckey_struct, seckey_s,
                   sizeof *seckey_struct, strlen(seckey_s),
                   &seckey_struct_len) == NULL ||
        seckey_struct_len != sizeof *seckey_struct) {
        exit_msg("base64 conversion failed - was an actual secret key given?");
    }
    sodium_free(seckey_s);
    if (memcmp(seckey_struct->sig_alg, SIGALG,
	       sizeof seckey_struct->sig_alg) != 0 &&
		memcmp(seckey_struct->sig_alg, SIGALG1,
				   sizeof seckey_struct->sig_alg) != 0) {
        exit_msg("Unsupported signature algorithm");
    }
    if (memcmp(seckey_struct->kdf_alg, KDFALG,
               sizeof seckey_struct->kdf_alg) != 0) {
        exit_msg("Unsupported key derivation function");
    }
    if (memcmp(seckey_struct->chk_alg, CHKALG,
               sizeof seckey_struct->chk_alg) != 0) {
        exit_msg("Unsupported checksum function");
    }
    if (get_password(pwd, PASSWORDMAXBYTES, "Password: ") != 0) {
        exit_msg("get_password()");
    }
    printf("Deriving a key from the password and decrypting the secret key... ");
    fflush(stdout);
    stream = xsodium_malloc(sizeof seckey_struct->keynum_sk);
    if (crypto_pwhash_scryptsalsa208sha256
        (stream, sizeof seckey_struct->keynum_sk, pwd, strlen(pwd),
         seckey_struct->kdf_salt,
         le64_load(seckey_struct->kdf_opslimit_le),
         le64_load(seckey_struct->kdf_memlimit_le)) != 0) {
        exit_err("Unable to complete key derivation - This probably means out of memory");
    }
    sodium_free(pwd);
    xor_buf((unsigned char *) (void *) &seckey_struct->keynum_sk, stream,
            sizeof seckey_struct->keynum_sk);
    sodium_free(stream);
    puts("done\n");
    seckey_chk(chk, seckey_struct);
    if (memcmp(chk, seckey_struct->keynum_sk.chk, sizeof chk) != 0) {
        exit_msg("Wrong password for that key");
    }
	sodium_memzero(chk, sizeof chk);//内存清零

    return seckey_struct;
}
#endif

static int
verify(PubkeyStruct *pubkey_struct, const char *message_file,
       const char *sig_file, int quiet, int output,int mode,unsigned char* userid)
{
    char           trusted_comment[TRUSTEDCOMMENTMAXBYTES];
    unsigned char  global_sig[crypto_sign_BYTES];
    FILE          *info_fp = stdout;
    unsigned char *sig_and_trusted_comment;
    SigStruct     *sig_struct;
    unsigned char *message;
    size_t         message_len;
    size_t         trusted_comment_len;
    int            hashed;

	int rv;
	clock_t start, end;
	double t;

    if (output != 0) {
        info_fp = stderr;
    }
    sig_struct = sig_load(sig_file, global_sig, &hashed,
                          trusted_comment, sizeof trusted_comment);

    message = message_load(&message_len, message_file, hashed);
	
	if (userid == NULL || *userid == 0)
	{
		userid = "ALICE123@YAHOO.COM";
	}
	size_t userid_len = strlen(userid);//sm2
	
    if (memcmp(sig_struct->keynum, pubkey_struct->keynum_pk.keynum,
               sizeof sig_struct->keynum) != 0) {
        fprintf(stderr, "Signature key id in %s is %" PRIX64 "\n"
                "but the key id in the public key is %" PRIX64 "\n",
                sig_file, le64_load(sig_struct->keynum),
                le64_load(pubkey_struct->keynum_pk.keynum));
        exit(1);
    }

	unsigned char r_sm2[32] = { "0" };
	unsigned char s_sm2[32] = { "0" };
	unsigned char e[32] = { "0" };

	int j;
	if(mode == 2)
		sm3_e(userid, userid_len, pubkey_struct->keynum_pk.pk, 32, pubkey_struct->keynum_pk.pk1, 32, message, message_len, e);
	start = clock();
	for (j = 0; j < 100; j++)
	{
		if (mode == 2)
		{

			memcpy(r_sm2, sig_struct->sig, 32);
			memcpy(s_sm2, sig_struct->sig + 32, 32);
			//pre process
#if DEBUG_SM2
			Print_Buf(r_sm2, 32);
			Print_Buf(s_sm2, 32);
#endif
			rv = sm2_verify(e, 32, r_sm2, 32, s_sm2, 32, pubkey_struct->keynum_pk.pk, 32, pubkey_struct->keynum_pk.pk1, 32);
			if (rv != 1 && quiet == 0)
			{
				fprintf(stderr, "Signature verification failed\n");
				exit(1);
			}

		}
		else
		{
			if (crypto_sign_verify_detached(sig_struct->sig, message, message_len,
				pubkey_struct->keynum_pk.pk) != 0) {
				if (quiet == 0) {
					fprintf(stderr, "Signature verification failed\n");
				}
				exit(1);
			}
		}
	}
    
	end = clock();
	t = (double)(end - start) / CLOCKS_PER_SEC;
	if (mode == 2)
	{
		printf("sm2_verify1 speed:%lf/s\n", (double)j / t);
	}
	else
	{
		printf("ed25519_verify1 speed:%lf/s\n", (double)j / t);
	}
	free(message);
    trusted_comment_len = strlen(trusted_comment);
    sig_and_trusted_comment = xmalloc((sizeof sig_struct->sig) +
                                      trusted_comment_len);
    memcpy(sig_and_trusted_comment, sig_struct->sig, sizeof sig_struct->sig);
    memcpy(sig_and_trusted_comment + sizeof sig_struct->sig, trusted_comment,
           trusted_comment_len);

	if(mode == 2)
		sm3_e(userid, userid_len, pubkey_struct->keynum_pk.pk, 32, pubkey_struct->keynum_pk.pk1, 32, sig_and_trusted_comment,
		(sizeof sig_struct->sig) + trusted_comment_len, e);
	start = clock();
	for (j = 0; j < 100; j++)
	{
		if (mode == 2)
		{//global_sig
			memcpy(r_sm2, global_sig, 32);
			memcpy(s_sm2, global_sig + 32, 32);

			//pre process
#if DEBUG_SM2
			Print_Buf(r_sm2, 32);
			Print_Buf(s_sm2, 32);
#endif
			rv = sm2_verify(e, 32, r_sm2, 32, s_sm2, 32, pubkey_struct->keynum_pk.pk, 32, pubkey_struct->keynum_pk.pk1, 32);
			if (rv != 1 && quiet == 0)
			{
				fprintf(stderr, "Comment signature verification failed\n");
				exit(1);
			}

		}
		else
		{
			if (crypto_sign_verify_detached(global_sig, sig_and_trusted_comment,
				(sizeof sig_struct->sig) + trusted_comment_len,
				pubkey_struct->keynum_pk.pk) != 0) {
				if (quiet == 0) {
					fprintf(stderr, "Comment signature verification failed\n");
				}
				exit(1);
			}
		}
	}
	end = clock();
	t = (double)(end - start) / CLOCKS_PER_SEC;
	if (mode == 2)
	{
		printf("sm2_verify2 speed:%lf/s\n", (double)j / t);
	}
	else
	{
		printf("ed25519_verify2 speed:%lf/s\n", (double)j / t);
	}

    sodium_free(pubkey_struct);
    free(sig_and_trusted_comment);
    free(sig_struct);


    if (quiet == 0) {
        fprintf(info_fp, "Signature and comment signature verified\n"
                "Trusted comment: %s\n", trusted_comment);
    } else if (quiet == 2) {
        fprintf(info_fp, "%s\n", trusted_comment);
    }
    if (output != 0 && output_file(message_file) != 0) {
        exit(2);
    }
    return 0;
}

#ifndef VERIFY_ONLY
static char *
default_trusted_comment(const char *message_file,unsigned long long message_len)
{
    char   *ret;
    time_t  ts = time(NULL);

    if (asprintf(&ret, "timestamp:%lu\tfile:%s\tfilesize:%lld bytes",
                 (unsigned long) ts, file_basename(message_file),message_len) < 0 ||ret == NULL) 
	{
		exit_err("asprintf()");
    }
    return ret;
}

static char *
append_sig_suffix(const char *message_file)
{
    char   *sig_file;
    size_t  message_file_len = strlen(message_file);

    sig_file = xmalloc(message_file_len + sizeof SIG_SUFFIX);
    memcpy(sig_file, message_file, message_file_len);
    memcpy(sig_file + message_file_len, SIG_SUFFIX, sizeof SIG_SUFFIX);

    return sig_file;
}//添加后缀.minisign

static char *
append_sig_sm2_suffix(const char *message_file)
{
	char   *sig_file;
	size_t  message_file_len = strlen(message_file);

	sig_file = xmalloc(message_file_len + sizeof SIG_SM2_SUFFIX);
	memcpy(sig_file, message_file, message_file_len);
	memcpy(sig_file + message_file_len, SIG_SM2_SUFFIX, sizeof SIG_SM2_SUFFIX);
	return sig_file;
}//添加后缀.minisig2

static void
sign(SeckeyStruct *seckey_struct, PubkeyStruct *pubkey_struct,
     const char *message_file, const char *sig_file, const char *comment,
     const char *trusted_comment, int hashed, int mode,unsigned char *userid)
{
    unsigned char  global_sig[crypto_sign_BYTES];
    SigStruct      sig_struct;
    FILE          *fp;
    unsigned char *message;
    unsigned char *sig_and_trusted_comment;
    char          *tmp_trusted_comment = NULL;
    size_t         comment_len;
    size_t         trusted_comment_len;
    size_t         message_len;


	unsigned char e[32] = { "0" };
	unsigned char r_sm2[32] = { "0" };
	unsigned char s_sm2[32] = { "0" };
	int rlen, slen;
	clock_t start, end;
	double t;

	if (userid == NULL || *userid == 0)
	{
		userid = "ALICE123@YAHOO.COM";
	}
	size_t userid_len = strlen(userid);//sm2

    
	memcpy(sig_struct.keynum, seckey_struct->keynum_sk.keynum,
		sizeof sig_struct.keynum);
	message = message_load(&message_len, message_file, hashed);

	if (trusted_comment == NULL || *trusted_comment == 0) {
		tmp_trusted_comment = default_trusted_comment(message_file, message_len);
		trusted_comment = tmp_trusted_comment;
	}

	int j;
	if( mode == 2) 
		sm3_e(userid, userid_len, pubkey_struct->keynum_pk.pk, 32, pubkey_struct->keynum_pk.pk1, 32, message, message_len, e);
	start = clock();
	for (j = 0; j < 100; j++)
	{
		if (mode == 1)
		{
			if (hashed != 0) {
				memcpy(sig_struct.sig_alg, SIGALG_HASHED, sizeof sig_struct.sig_alg);
			}
			else {
				memcpy(sig_struct.sig_alg, SIGALG, sizeof sig_struct.sig_alg);
			}
			crypto_sign_detached(sig_struct.sig, NULL, message, message_len,
				seckey_struct->keynum_sk.sk);
		}
		else if (mode == 2)//sm2 sign
		{
			if (hashed != 0) {
				memcpy(sig_struct.sig_alg, SIGALG1_HASHED, sizeof sig_struct.sig_alg);
			}
			else {
				memcpy(sig_struct.sig_alg, SIGALG1, sizeof sig_struct.sig_alg);
			}

			sm2_sign(e, 32, seckey_struct->keynum_sk.sk, 32, r_sm2, &rlen, s_sm2, &slen);
#if DEBUG_SM2
			Print_Buf(r_sm2, 32);
			Print_Buf(s_sm2, 32);
#endif
			memcpy(sig_struct.sig, r_sm2, 32);
			memcpy(sig_struct.sig + 32, s_sm2, 32);
		}
	}
	end = clock();
	t = (double)(end - start) / CLOCKS_PER_SEC;
	if (mode == 2)
	{
		printf("sm2_sign1 speed:%lf/s\n", (double)j / t);
	}
	else
	{
		printf("ed25519_sign1 speed:%lf/s\n", (double)j / t);
	}

	free(message);
    if ((fp = fopen(sig_file, "w")) == NULL) {
        exit_err(sig_file);
    }
    comment_len = strlen(comment);
    assert(strrchr(comment, '\r') == NULL && strrchr(comment, '\n') == NULL);
    assert(COMMENTMAXBYTES > sizeof COMMENT_PREFIX);
    if (comment_len >= COMMENTMAXBYTES - sizeof COMMENT_PREFIX) {
        fprintf(stderr, "Warning: comment too long. "
                "This breaks compatibility with signify.\n");
    }
    xfprintf(fp, "%s%s\n", COMMENT_PREFIX, comment);
    xfput_b64(fp, (unsigned char *) (void *) &sig_struct, sizeof sig_struct);

    xfprintf(fp, "%s%s\n", TRUSTED_COMMENT_PREFIX, trusted_comment);
    trusted_comment_len = strlen(trusted_comment);
    assert(strrchr(trusted_comment, '\r') == NULL &&
           strrchr(trusted_comment, '\n') == NULL);
    if (trusted_comment_len >=
        TRUSTEDCOMMENTMAXBYTES - sizeof TRUSTED_COMMENT_PREFIX) {
        exit_msg("Trusted comment too long");
    }

    sig_and_trusted_comment = xmalloc((sizeof sig_struct.sig) +
                                      trusted_comment_len);
    memcpy(sig_and_trusted_comment, sig_struct.sig, sizeof sig_struct.sig);
    memcpy(sig_and_trusted_comment + sizeof sig_struct.sig, trusted_comment,
           trusted_comment_len);
    
	if(mode == 2)
		sm3_e(userid, userid_len, pubkey_struct->keynum_pk.pk, 32, pubkey_struct->keynum_pk.pk1, 32, sig_and_trusted_comment, (sizeof sig_struct.sig) + trusted_comment_len, e);
	start = clock();
	for (j = 0; j < 100; j++)
	{
		if (mode == 1)
		{
			if (crypto_sign_detached(global_sig, NULL, sig_and_trusted_comment,
				(sizeof sig_struct.sig) + trusted_comment_len,
				seckey_struct->keynum_sk.sk) != 0) {
				exit_msg("Unable to compute a signature");
			}

		}
		else if (mode == 2)
		{
			
			sm2_sign(e, 32, seckey_struct->keynum_sk.sk, 32, r_sm2, &rlen, s_sm2, &slen);
#if DEBUG_SM2
			Print_Buf(r_sm2, 32);
			Print_Buf(s_sm2, 32);
#endif
			memcpy(global_sig, r_sm2, 32);
			memcpy(global_sig + 32, s_sm2, 32);
		}
	}
	end = clock();
	t = (double)(end - start) / CLOCKS_PER_SEC;
	if (mode == 2)
	{
		printf("sm2_sign2 speed:%lf/s\n", (double)j / t);
	}
	else
	{
		printf("ed25519_sign2 speed:%lf/s\n", (double)j / t);
	}
	//free(e);
    xfput_b64(fp, (unsigned char *) (void *) &global_sig, sizeof global_sig);
    xfclose(fp);
    free(sig_and_trusted_comment);
    free(tmp_trusted_comment);
}


static int
sign_all(SeckeyStruct *seckey_struct, PubkeyStruct *pubkey_struct,
         const char *message_file, const char *additional_files[], int additional_count,
         const char *sig_file, const char *comment, const char *trusted_comment,
         int hashed,int mode,char *useid)
{
    char *additional_sig_file;
    int   i;
	
#if DEBUG_SM2
	Print_Buf(seckey_struct->keynum_sk.sk, 64);
	Print_Buf(pubkey_struct->keynum_pk.pk, 32);
	Print_Buf(pubkey_struct->keynum_pk.pk1, 32);
#endif
	sign(seckey_struct, pubkey_struct, message_file, sig_file, comment,
		trusted_comment, hashed, mode,useid);
    for (i = 0; i < additional_count; i++) {
        additional_sig_file = append_sig_suffix(additional_files[i]);
		sign(seckey_struct, pubkey_struct, additional_files[i],
			additional_sig_file, comment, trusted_comment, hashed, mode, useid);
        free(additional_sig_file);
    }
    sodium_free(seckey_struct);
    sodium_free(pubkey_struct);
	printf("Success sign!");
    return 0;
}

static void
abort_on_existing_key_file(const char *file)
{
    FILE *fp;
    int   exists = 0;

    if ((fp = fopen(file, "r")) != NULL) {
        exists = 1;
        fclose(fp);
    }
    if (exists != 0) {
        fprintf(stderr, "Key generation aborted:\n"
                "%s already exists.\n\n"
                "If you really want to overwrite the existing key pair, add the -f switch to \n"
                "force this operation.\n", file);
        exit(1);
    }
}//key exists

static void
abort_on_existing_key_files(const char *pk_file, const char *sk_file,
                            int force)
{
    if (force == 0) {
        abort_on_existing_key_file(pk_file);
        abort_on_existing_key_file(sk_file);
    }
}//judge exist

static void
write_pk_file(const char *pk_file, const PubkeyStruct *pubkey_struct,int mode)
{
    FILE *fp;

    if ((fp = fopen(pk_file, "w")) == NULL) {
        exit_err(pk_file);
    }
	if (mode == 2)
	{
		xfprintf(fp, COMMENT_PREFIX "minisign public sm2 key %" PRIX64 "\n",
			le64_load(pubkey_struct->keynum_pk.keynum));
	}
	else
	{
		xfprintf(fp, COMMENT_PREFIX "minisign public key %" PRIX64 "\n",
			le64_load(pubkey_struct->keynum_pk.keynum));
	}
	xfput_b64(fp, (const unsigned char *)(const void *)pubkey_struct,
              sizeof *pubkey_struct);
    xfclose(fp);
}

static int
generate(const char *pk_file, const char *sk_file, const char *comment,
         int force,int mode)//密钥生成
{
    char          *pwd = xsodium_malloc(PASSWORDMAXBYTES);
    char          *pwd2 = xsodium_malloc(PASSWORDMAXBYTES);
    SeckeyStruct  *seckey_struct = xsodium_malloc(sizeof(SeckeyStruct));
    PubkeyStruct  *pubkey_struct = xsodium_malloc(sizeof(PubkeyStruct));
    unsigned char *stream ;
    FILE          *fp;
    unsigned long  kdf_memlimit;
    unsigned long  kdf_opslimit;

    abort_on_existing_key_files(pk_file, sk_file, force);
    randombytes_buf(seckey_struct->keynum_sk.keynum,
                    sizeof seckey_struct->keynum_sk.keynum);
	if (mode == 2)
	{
/*
	sm2 parameter
*/
		unsigned char skA_sm2[] = { 0x12,0x8B,0x2F,0xA8,0xBD,0x43,0x3C,0x6C,0x06,0x8C,0x8D,0x80,0x3D,0xFF,0x79,0x79,0x2A,0x51,0x9A,0x55,0x17,0x1B,0x1B,0x65,0x0C,0x23,0x66,0x1D,0x15,0x89,0x72,0x63 };
		unsigned char pkAx_sm2[] = { 0x0A,0xE4,0xC7,0x79,0x8A,0xA0,0xF1,0x19,0x47,0x1B,0xEE,0x11,0x82,0x5B,0xE4,0x62,0x02,0xBB,0x79,0xE2,0xA5,0x84,0x44,0x95,0xE9,0x7C,0x04,0xFF,0x4D,0xF2,0x54,0x8A };
		unsigned char pkAy_sm2[] = { 0x7C,0x02,0x40,0xF8,0x8F,0x1C,0xD4,0xE1,0x63,0x52,0xA7,0x3C,0x17,0xB7,0xF1,0x6F,0x07,0x35,0x3E,0x53,0xA1,0x76,0xD6,0x84,0xA9,0xFE,0x0C,0x6B,0xB7,0x98,0xE8,0x57 };
		int wxlen, wylen, privkeylen;
#if !DEBUG_SM2
		sm2_keygen(pkAx_sm2, &wxlen, pkAy_sm2, &wylen, skA_sm2, &privkeylen);
#endif
		memcpy(seckey_struct->keynum_sk.sk, skA_sm2, sizeof seckey_struct->keynum_sk.sk);
		memcpy(pubkey_struct->keynum_pk.pk, pkAx_sm2, sizeof pubkey_struct->keynum_pk.pk);//pka
		memcpy(pubkey_struct->keynum_pk.pk1, pkAy_sm2, sizeof pubkey_struct->keynum_pk.pk1);//save key pky
		memcpy(seckey_struct->sig_alg, SIGALG1, sizeof seckey_struct->sig_alg);
		memcpy(pubkey_struct->sig_alg, SIGALG1, sizeof pubkey_struct->sig_alg);

	}
	else
	{
		crypto_sign_keypair(pubkey_struct->keynum_pk.pk,
			seckey_struct->keynum_sk.sk);
		memcpy(seckey_struct->sig_alg, SIGALG, sizeof seckey_struct->sig_alg);
		memcpy(pubkey_struct->sig_alg, SIGALG, sizeof pubkey_struct->sig_alg);
	}
	
    memcpy(seckey_struct->kdf_alg, KDFALG, sizeof seckey_struct->kdf_alg);
    memcpy(seckey_struct->chk_alg, CHKALG, sizeof seckey_struct->chk_alg);
    memcpy(pubkey_struct->keynum_pk.keynum, seckey_struct->keynum_sk.keynum,
           sizeof pubkey_struct->keynum_pk.keynum);
    

    puts("Please enter a password to protect the secret key.\n");
    if (get_password(pwd, PASSWORDMAXBYTES, "Password: ") != 0 ||
        get_password(pwd2, PASSWORDMAXBYTES, "Password (one more time): ") != 0) {
        exit_msg("get_password()");
    }
    if (strcmp(pwd, pwd2) != 0) {
        exit_msg("Passwords don't match");
    }
    printf("Deriving a key from the password in order to encrypt the secret key... ");
    fflush(stdout);
    stream = xsodium_malloc(sizeof seckey_struct->keynum_sk);
    randombytes_buf(seckey_struct->kdf_salt, sizeof seckey_struct->kdf_salt);
    kdf_opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE;
    kdf_memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE;//highly sensitive data

    while (crypto_pwhash_scryptsalsa208sha256
           (stream, sizeof seckey_struct->keynum_sk, pwd, strlen(pwd),
               seckey_struct->kdf_salt, kdf_opslimit, kdf_memlimit) != 0) {
        kdf_opslimit /= 2;
        kdf_memlimit /= 2;
        if (kdf_opslimit < crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN ||
            kdf_memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN) {
            exit_err("Unable to complete key derivation - More memory would be needed");
        }
    }
    sodium_free(pwd);
    sodium_free(pwd2);
    if (kdf_memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE) {
        fprintf(stderr, "Warning: due to limited memory the KDF used less "
                "memory than the default\n");
    }
    le64_store(seckey_struct->kdf_opslimit_le, kdf_opslimit);
    le64_store(seckey_struct->kdf_memlimit_le, kdf_memlimit);
    seckey_chk(seckey_struct->keynum_sk.chk, seckey_struct);
    xor_buf((unsigned char *) (void *) &seckey_struct->keynum_sk, stream,
            sizeof seckey_struct->keynum_sk);
    sodium_free(stream);
    puts("done\n");

    abort_on_existing_key_files(pk_file, sk_file, force);
    if (basedir_create_useronly(sk_file) != 0) {
        fprintf(stderr, "Warning: you may have to create the parent directory\n");
    }
    if ((fp = fopen_create_useronly(sk_file)) == NULL) {
        exit_err(sk_file);
    }

    xfprintf(fp, "%s%s\n", COMMENT_PREFIX, comment);
    xfput_b64(fp, (unsigned char *) (void *) seckey_struct,
              sizeof *seckey_struct);
    xfclose(fp);
    sodium_free(seckey_struct);

    write_pk_file(pk_file, pubkey_struct,mode);

    printf("The secret key was saved as %s - Keep it secret!\n", sk_file);
    printf("The public key was saved as %s - That one can be public.\n\n", pk_file);
    puts("Files signed using this key pair can be verified with the following command:\n");
    printf("minisign -Vm <file> ");
	if (mode == 2)
	{
		printf("-M -P ");
	}
	else
	{
		printf("-P ");
	}
    xfput_b64(stdout, (unsigned char *) (void *) pubkey_struct,
              sizeof *pubkey_struct);
    puts("");
    sodium_free(pubkey_struct);

    return 0;
}


static int
recreate_pk(const char *pk_file, const char *sk_file, int force,int mode)
{
    SeckeyStruct   *seckey_struct;
    PubkeyStruct    pubkey_struct;

    if (force == 0) {
        abort_on_existing_key_file(pk_file);
    }
    if ((seckey_struct = seckey_load(sk_file)) == NULL) {
        return -1;
    }
    memcpy(pubkey_struct.sig_alg, seckey_struct->sig_alg,
           sizeof pubkey_struct.sig_alg);
    memcpy(pubkey_struct.keynum_pk.keynum, seckey_struct->keynum_sk.keynum,
           sizeof pubkey_struct.keynum_pk.keynum);
    assert(sizeof seckey_struct->keynum_sk.sk > crypto_sign_PUBLICKEYBYTES);//32
	if (mode == 2)
	{
		unsigned char skA_sm2[32],pkAx_sm2[32], pkAy_sm2[32];
		memcpy(skA_sm2, seckey_struct->keynum_sk.sk, 32);
		sm2_recreate_pk(skA_sm2, 32, pkAx_sm2, pkAy_sm2);
		memcpy(pubkey_struct.keynum_pk.pk, pkAx_sm2, sizeof pubkey_struct.keynum_pk.pk);
		memcpy(pubkey_struct.keynum_pk.pk1, pkAy_sm2, sizeof pubkey_struct.keynum_pk.pk1);//save pk
	}
	else
	{
		memcpy(pubkey_struct.keynum_pk.pk, seckey_struct->keynum_sk.sk +
			(sizeof seckey_struct->keynum_sk.sk) - crypto_sign_PUBLICKEYBYTES,
			sizeof pubkey_struct.keynum_pk.pk);
		memcpy(pubkey_struct.keynum_pk.pk1, seckey_struct->keynum_sk.sk +
			(sizeof seckey_struct->keynum_sk.sk) - crypto_sign_PUBLICKEYBYTES,
			sizeof pubkey_struct.keynum_pk.pk1);
	}
	sodium_free(seckey_struct);

    write_pk_file(pk_file, &pubkey_struct,mode);

    return 0;
}

#endif

#ifndef VERIFY_ONLY
static char *
sig_config_dir(void)
{
    const char *config_dir_env;
    char       *config_dir;
    char       *home_dir;

    config_dir = NULL;
    if ((config_dir_env = getenv(SIG_DEFAULT_CONFIG_DIR_ENV_VAR)) != NULL) {
        config_dir = xstrdup(config_dir_env);
    } else if ((home_dir = get_home_dir()) != NULL) {
        if (asprintf(&config_dir, "%s%c%s", home_dir, DIR_SEP,
                     SIG_DEFAULT_CONFIG_DIR) < 0 || config_dir == NULL) {
            exit_err("asprintf()");
        }
        free(home_dir);
    }
    return config_dir;//C:\\Users\\asus\\.minisign
}

static char *
sig_default_skfile(void)
{
    char       *config_dir;
    char       *skfile;

    if ((config_dir = sig_config_dir()) == NULL) {
        skfile = xstrdup(SIG_DEFAULT_SKFILE);
        return skfile;
    }
    if (asprintf(&skfile, "%s%c%s", config_dir, DIR_SEP,
                 SIG_DEFAULT_SKFILE) < 0 ||
        skfile == NULL) {
        exit_err("asprintf()");
    }
    free(config_dir);

    return skfile;
}

static char *
sig_sm2_default_skfile(void)//add sm2 version
{
	char       *config_dir;
	char       *skfile;

	if ((config_dir = sig_config_dir()) == NULL) {
		skfile = xstrdup(SIG_DEFAULT_SM2_SKFILE);
		return skfile;
	}
	if (asprintf(&skfile, "%s%c%s", config_dir, DIR_SEP,
		SIG_DEFAULT_SM2_SKFILE) < 0 ||
		skfile == NULL) {
		exit_err("asprintf()");
	}
	free(config_dir);

	return skfile;
}
#endif

extern struct ECC bz;
extern struct ECC bz2;


int
main(int argc, char **argv)
{
    const char    *pk_file = NULL;
#ifndef VERIFY_ONLY
	char          *sk_file = NULL;
#endif
    const char    *sig_file = NULL;
    const char    *message_file = NULL;
    const char    *comment = NULL;
    const char    *pubkey_s = NULL;
    const char    *trusted_comment = NULL;
    unsigned char  opt_seen[16] = { 0 };
    int            opt_flag;
    int            hashed = 0;
    int            quiet = 0;
    int            output = 0;
    int            force = 0;
    Action         action = ACTION_NONE;

	int			   mode = 1;//default	
	unsigned char	  *userid = NULL;

    while ((opt_flag = getopt(argc, argv, getopt_options)) != -1) {
        switch(opt_flag) {
#ifndef VERIFY_ONLY
        case 'G':
            if (action != ACTION_NONE && action != ACTION_GENERATE) {
                usage();
            }
            action = ACTION_GENERATE;
            break;
        case 'S':
            if (action != ACTION_NONE && action != ACTION_SIGN) {
                usage();
            }
            action = ACTION_SIGN;
            break;
        case 'R':
            if (action != ACTION_NONE && action != ACTION_RECREATE_PK) {
                usage();
            }
            action = ACTION_RECREATE_PK;
            break;
#endif
        case 'V':
            if (action != ACTION_NONE && action != ACTION_VERIFY) {
                usage();
            }
            action = ACTION_VERIFY;
            break;
#ifndef VERIFY_ONLY
        case 'c':
            comment = optarg;
            break;
        case 'f':
            force = 1;
            break;
#endif
        case 'h':
            usage();
        case 'H':
            hashed = 1;
            break;
        case 'm':
            message_file = optarg;
            break;
        case 'o':
            output = 1;
            break;
        case 'p':
            pk_file = optarg;
            break;
        case 'P':
            pubkey_s = optarg;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'Q':
            quiet = 2;
            break;
#ifndef VERIFY_ONLY
        case 's':
            free(sk_file);
            sk_file = xstrdup(optarg);
            break;
        case 't':
            trusted_comment = optarg;
            break;
#endif
        case 'x':
            sig_file = optarg;
            break;
        case 'v':
            puts(VERSION_STRING);
            return 0;
//ADD SM2
		case 'u':
			userid = optarg;
			break;
		case 'T':
			printf("Test success\n");
			break;
		case 'M':
			mode = 2;//generate/sign/verify with sm2
			printf("You are using sm%d for the following actions!  \n",mode);
			printf("\n");
			break;
        case '?':
            usage();
        }
        if (opt_flag > 0 && opt_flag <= (int) sizeof opt_seen / 8) {
            if ((opt_seen[opt_flag / 8] & (1U << (opt_flag & 7))) != 0) {
                fprintf(stderr, "Duplicate option: -- %c\n\n", opt_flag);
                usage();
            }
            opt_seen[opt_flag / 8] |= 1U << (opt_flag & 7);
        }
    }
    if (sodium_init() != 0) {
        fprintf(stderr, "Unable to initialize the Sodium library\n");
        return 2;
    }//soudium 初始化失败

	switch (action) {
#ifndef VERIFY_ONLY
	case ACTION_GENERATE:
		if (mode == 2) {
			//sm2gen
			sk_file = sig_sm2_default_skfile();
			if (comment == NULL || *comment == 0) {
				comment = SECRETKEY_SM2_DEFAULT_COMMENT;
			}
			if (pk_file == NULL) {
				pk_file = SIG_DEFAULT_SM2_PKFILE;
			}
		}
		else {
			sk_file = sig_default_skfile();
			if (comment == NULL || *comment == 0) {
				comment = SECRETKEY_DEFAULT_COMMENT;
			}
			if (pk_file == NULL) {
				pk_file = SIG_DEFAULT_PKFILE;
			}
		}
		return generate(pk_file, sk_file, comment, force, mode) != 0;
	case ACTION_SIGN:
		if (message_file == NULL) {
			usage();
		}//未输入文件
		FILE *ft;
		if ((ft = fopen(message_file, "rb")) == NULL) {
			exit_err(message_file);
		}
		if (mode == 2) {
			//sm2sig
			sk_file = sig_sm2_default_skfile();
			if (sig_file == NULL || *sig_file == 0) {
				sig_file = append_sig_sm2_suffix(message_file);
			}
			if (comment == NULL || *comment == 0) {
				comment = DEFAULT_SM2_COMMENT;
			}
			if (pk_file == NULL && pubkey_s == NULL) {
				pk_file = SIG_DEFAULT_SM2_PKFILE;
			}
		}
		else {
			sk_file = sig_default_skfile();
			if (sig_file == NULL || *sig_file == 0) {
				sig_file = append_sig_suffix(message_file);
			}
			if (comment == NULL || *comment == 0) {
				comment = DEFAULT_COMMENT;
			}

		}

		return sign_all(seckey_load(sk_file),
			((pk_file != NULL || pubkey_s != NULL) ?
				pubkey_load(pk_file, pubkey_s) : NULL),
			message_file, (const char **)&argv[optind], argc - optind,
			sig_file, comment, trusted_comment, hashed, mode, userid) != 0;
	case ACTION_RECREATE_PK:
		if (mode == 1)
		{
			sk_file = sig_default_skfile();//add
			if(pk_file == NULL)
				pk_file = SIG_DEFAULT_PKFILE;

		}
		else
		{
			sk_file = sig_sm2_default_skfile();
			if (pk_file == NULL)
				pk_file = SIG_DEFAULT_SM2_PKFILE;
		}
		
		return recreate_pk(pk_file, sk_file, force, mode) != 0;
#endif
    case ACTION_VERIFY:
        if (message_file == NULL) {
            usage();
        }
		if (mode == 2)
		{
			if (sig_file == NULL || *sig_file == 0) {
				sig_file = append_sig_sm2_suffix(message_file);
			}
			if (pk_file == NULL && pubkey_s == NULL) {
				pk_file = SIG_DEFAULT_SM2_PKFILE;
			}
		}
		else {
			if (sig_file == NULL || *sig_file == 0) {
				sig_file = append_sig_suffix(message_file);
			}
			if (pk_file == NULL && pubkey_s == NULL) {
				pk_file = SIG_DEFAULT_PKFILE;
			}
			
		}
		return verify(pubkey_load(pk_file, pubkey_s), message_file,
			sig_file, quiet, output, mode,userid) != 0;
    default:
        usage();
    }
	
	printf("Success!!!");
    return 0;


}
