/****************************************************************************
*																			*
*						cryptlib SSHv2 Session Management					*
*						Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "ssh.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../session/session.h"
  #include "../session/ssh.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSH2

/* Tables mapping SSHv2 algorithm names to cryptlib algorithm IDs, in 
   preferred algorithm order.  See the comment in ssh2_svr.c for the reason
   behind the difference in encryption algorithm tables for client and 
   server */

static const FAR_BSS ALGO_STRING_INFO algoStringKeyexTbl[] = {
	{ "diffie-hellman-group-exchange-sha1", CRYPT_ALGO_DES },	/* Placeholder algo ID */
	{ "diffie-hellman-group1-sha1", CRYPT_ALGO_DH },
	{ NULL, CRYPT_ALGO_NONE }
	};

static const FAR_BSS ALGO_STRING_INFO algoStringCoprTbl[] = {
	{ "none", CRYPT_ALGO_DES },		/* Placeholder algo ID */
	{ NULL, CRYPT_ALGO_NONE }
	};

static const FAR_BSS ALGO_STRING_INFO algoStringPubkeyTbl[] = {
	{ "ssh-rsa", CRYPT_ALGO_RSA },
	{ "ssh-dss", CRYPT_ALGO_DSA },
	{ NULL, CRYPT_ALGO_NONE }
	};

static const FAR_BSS ALGO_STRING_INFO algoStringEncrTblClient[] = {
	{ "3des-cbc", CRYPT_ALGO_3DES },
	{ "aes128-cbc", CRYPT_ALGO_AES },
	{ "blowfish-cbc", CRYPT_ALGO_BLOWFISH },
	{ "cast128-cbc", CRYPT_ALGO_CAST },
	{ "idea-cbc", CRYPT_ALGO_IDEA },
	{ "arcfour", CRYPT_ALGO_RC4 },
	{ NULL, CRYPT_ALGO_NONE }
	};
static const FAR_BSS ALGO_STRING_INFO algoStringEncrTblServer[] = {
	{ "3des-cbc", CRYPT_ALGO_3DES },
	{ "blowfish-cbc", CRYPT_ALGO_BLOWFISH },
	{ "cast128-cbc", CRYPT_ALGO_CAST },
	{ "idea-cbc", CRYPT_ALGO_IDEA },
	{ "arcfour", CRYPT_ALGO_RC4 },
	{ NULL, CRYPT_ALGO_NONE }
	};

static const FAR_BSS ALGO_STRING_INFO algoStringMACTbl[] = {
	{ "hmac-sha1", CRYPT_ALGO_HMAC_SHA },
	{ "hmac-md5", CRYPT_ALGO_HMAC_MD5 },
	{ NULL, CRYPT_ALGO_NONE }
	};

static const FAR_BSS ALGO_STRING_INFO algoStringUserauthentTbl[] = {
	{ "password", CRYPT_ALGO_DES },		/* Placeholder algo ID */
	{ "publickey", CRYPT_ALGO_RSA },
	{ NULL, CRYPT_ALGO_NONE }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Load the fixed SSHv2 DH key into a context.  The prime is the value
   2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }, from the Oakley spec
   (RFC 2412, other locations omit the q value).  Unfortunately the choice 
   of q leads to horribly inefficient operations since it's 860 bits larger 
   than it needs to be */

static const FAR_BSS BYTE dh1024SPKI[] = {
	0x30, 0x82, 0x01, 0x21,
		0x30, 0x82, 0x01, 0x17,
			0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01,
			0x30, 0x82, 0x01, 0x0A,
				0x02, 0x81, 0x81, 0x00,		/* p */
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
					0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
					0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
					0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
					0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
					0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
					0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
					0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
					0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
					0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
					0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
					0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
					0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
					0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0x02, 0x01,					/* g */
					0x02,
				0x02, 0x81, 0x80,			/* q */
					0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4, 0x61, 0x1A,
					0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68,
					0x94, 0x81, 0x27, 0x04, 0x45, 0x33, 0xE6, 0x3A,
					0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91,
					0x28, 0xA5, 0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E,
					0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
					0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B,
					0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8, 0xE1, 0x22,
					0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63,
					0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1B, 0xF6, 0xB5,
					0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6,
					0xF7, 0x1C, 0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2,
					0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
					0x24, 0x94, 0x33, 0x28, 0xF6, 0x73, 0x29, 0xC0,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x03, 0x04, 0x00,
			0x02, 0x01, 0x00 };				/* y */

/* Additional DH values, from RFC 3526.  The 1536-bit value is widely used 
   in IKE, and has the prime value 
   2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }.  The 2048-bit
   value has the prime value 
   2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }, and the 3072-bit
   value has the prime value
   2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }.  All have a 
   generator of 2 */

static const FAR_BSS BYTE dh1536SSH[] = {
	0x00, 0x00, 0x00, 0xD8,
		0x00, 0x00, 0x00, 0x06,		/* Algorithm ID */
			's', 's', 'h', '-', 'd', 'h',
		0x00, 0x00, 0x00, 0xC1,		/* p */
			0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
			0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
			0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
			0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 
			0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 
			0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
			0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
			0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 
			0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
			0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 
			0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
			0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
			0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 
			0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 
			0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
			0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 
			0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 
			0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
			0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 
			0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27, 
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x01,		/* g */
			0x02
	};

static const FAR_BSS BYTE dh2048SSH[] = {
	0x00, 0x00, 0x01, 0x18,
		0x00, 0x00, 0x00, 0x06,		/* Algorithm ID */
			's', 's', 'h', '-', 'd', 'h',
		0x00, 0x00, 0x01, 0x01,		/* p */
			0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
			0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
			0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
			0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 
			0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 
			0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
			0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
			0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 
			0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
			0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 
			0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
			0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
			0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 
			0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 
			0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
			0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 
			0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 
			0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
			0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 
			0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 
			0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
			0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 
			0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 
			0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
			0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 
			0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 
			0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
			0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x01,		/* g */
			0x02
	};

static const FAR_BSS BYTE dh3072SSH[] = {
	0x00, 0x00, 0x01, 0x98,
		0x00, 0x00, 0x00, 0x06,		/* Algorithm ID */
			's', 's', 'h', '-', 'd', 'h',
		0x00, 0x00, 0x01, 0x81,		/* p */
			0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
			0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
			0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
			0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 
			0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 
			0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
			0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
			0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 
			0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
			0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 
			0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
			0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
			0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 
			0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 
			0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
			0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 
			0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 
			0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
			0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 
			0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 
			0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
			0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 
			0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 
			0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
			0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 
			0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 
			0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
			0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 
			0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33, 
			0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
			0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 
			0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 
			0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
			0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 
			0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D, 
			0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
			0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 
			0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 
			0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
			0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 
			0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 
			0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
			0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 
			0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA, 
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x01,		/* g */
			0x02
	};

int initDHcontext( CRYPT_CONTEXT *iCryptContext, int *keySize, 
				   const void *keyData, const int keyDataLength,
				   const int requestedKeySize )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	int length, status;

	assert( ( keyData != NULL && keyDataLength > 0 && \
			  isReadPtr( keyData, keyDataLength ) && \
			  requestedKeySize == CRYPT_UNUSED ) || \
			( keyData == NULL && keyDataLength == 0 && \
			  requestedKeySize == CRYPT_USE_DEFAULT ) || \
			( keyData == NULL && keyDataLength == 0 && \
			  requestedKeySize >= bitsToBytes( MIN_PKCSIZE_BITS ) && \
			  requestedKeySize <= CRYPT_MAX_PKCSIZE ) );

	*iCryptContext = CRYPT_ERROR;
	*keySize = 0;

	/* Create the DH context */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DH );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the key into the context */
	setMessageData( &msgData, "SSH DH key", 10 );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusOK( status ) )
		{
		int keyType = CRYPT_IATTRIBUTE_KEY_SSH2;

		/* If we're being given externally-supplied DH key components, load 
		   them */
		if( keyData != NULL )
			{ setMessageData( &msgData, ( void * ) keyData, keyDataLength ); }
		else
			{
			/* Get the actual key size based on the requested key size.  The
			   spec requires that we use the smallest key size that's larger 
			   than the requested one, we allow for a small amount of slop 
			   to ensure that we don't scale up to some huge key size if the 
			   client's keysize calculation is off by a few bits */
			const int actualKeySize = \
					( requestedKeySize == CRYPT_USE_DEFAULT ) ? SSH2_DEFAULT_KEYSIZE : \
					( requestedKeySize < 128 + 8 ) ? bitsToBytes( 1024 ) : \
					( requestedKeySize < 192 + 8 ) ? bitsToBytes( 1536 ) : \
					( requestedKeySize < 256 + 8 ) ? bitsToBytes( 2048 ) : \
					( requestedKeySize < 384 + 8 ) ? bitsToBytes( 3072 ) : \
					0;

			/* If the request key size corresponds (at least approximately) 
			   to a built-in DH value, load the built-in key value, 
			   otherwise generate a new one.  In theory we should probably 
			   generate a new DH key each time:
			   
				status = krnlSendMessage( createInfo.cryptHandle,
										  IMESSAGE_SETATTRIBUTE, 
										  ( void * ) &requestedKeySize,
										  CRYPT_CTXINFO_KEYSIZE );
				if( cryptStatusOK( status ) )
					status = krnlSendMessage( createInfo.cryptHandle,
											  IMESSAGE_CTX_GENKEY, NULL, 
											  FALSE );
			   
			   however because the handshake is set up so that the client 
			   (rather than the server) chooses the key size, we can't 
			   actually perform the generation until we're in the middle of 
			   the handshake.  This means that the server will grind to a 
			   halt during each handshake as it generates a new key of 
			   whatever size takes the client's fancy (it also leads to a 
			   nice potential DoS attack on the server).  To avoid this 
			   problem, we use fixed keys for common sizes, only generating 
			   a key if it's absolutely necessary */
			switch( actualKeySize )
				{
				case bitsToBytes( 1024 ):
					setMessageData( &msgData, ( void * ) dh1024SPKI, 
									sizeof( dh1024SPKI ) );
					keyType = CRYPT_IATTRIBUTE_KEY_SPKI;
					break;

				case bitsToBytes( 1536 ):
					setMessageData( &msgData, ( void * ) dh1536SSH, 
									sizeof( dh1536SSH ) );
					break;

				case bitsToBytes( 2048 ):
					setMessageData( &msgData, ( void * ) dh2048SSH, 
									sizeof( dh2048SSH ) );
					break;

				case bitsToBytes( 3072 ):
				default:		/* Hier ist der mast zu ende */
					setMessageData( &msgData, ( void * ) dh3072SSH, 
									sizeof( dh3072SSH ) );
					break;
				}
			}
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  keyType );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_GETATTRIBUTE, &length,
								  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		{
		assert( NOTREACHED );
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;
	*keySize = length;
	return( CRYPT_OK );
	}

/* Convert an SSHv2 algorithm list to a cryptlib ID in preferred-algorithm
   order.  For some bizarre reason the algorithm information is communicated
   as a comma-delimited list (in an otherwise binary protocol), so we have
   to unpack and pack them into this cumbersome format alongside just
   choosing which algorithm to use.  In addition, the algorithm selection
   mechanism differs depending on whether we're the client or server, and 
   what set of algorithms we're matching.  Unlike SSL, which uses the 
   offered-suites/chosen-suites mechanism, in SSHv2 both sides offer a 
   selection of cipher suites and the server chooses the first one that 
   appears on both it and the client's list, with special-case handling for
   the keyex and signature algorithms if the match isn't the first one on 
   the list.  This means that the client can choose as it pleases from the 
   server's list if it waits for the server hello (see the comment in the 
   client/server hello handling code on the annoying nature of this portion 
   of the SSHv2 handshake), but the server has to perform a complex double-
   match of its own vs.the client's list.  The cases that we need to handle 
   are:

	get the first matching algorithm, used by the server to match the client.

	get the first matching algorithm and warn if it isn't the first one on 
		the list of possible algorithms, used by the server to match the 
		client for the keyex and public-key algorithms.

	get the best matching algorithm (that is, the one corresponding to the
		strongest crypto mechanism), used by the client to match the server.

   This is a sufficiently complex and screwball function that we need to 
   define a composite structure to pass all of the control information in 
   and out */

typedef enum {
	GETALGO_NONE,			/* No match action */
	GETALGO_FIRST_MATCH,	/* Get first matching algorithm */
	GETALGO_FIRST_MATCH_WARN,/* Get first matching algo, warn if not first */
	GETALGO_BEST_MATCH,		/* Get best matching algorithm */
	GETALGO_LAST			/* Last possible match action */
	} GETALGO_TYPE;

typedef struct {
	const ALGO_STRING_INFO *algoInfo;/* Algorithm selection info */
	CRYPT_ALGO_TYPE preferredAlgo;	/* Preferred algo for first-match */
	GETALGO_TYPE getAlgoType;		/* Type of match to perform */
	CRYPT_ALGO_TYPE algo;			/* Matched algorithm */
	int algoStringLength;			/* Length of algorithm string */
	BOOLEAN prefAlgoMismatch;		/* First match != preferredAlgo */
	} ALGOID_INFO;

#define setAlgoIDInfo( algoIDInfo, algoStrInfo, prefAlgo, getType ) \
	{ \
	memset( ( algoIDInfo ), 0, sizeof( ALGOID_INFO ) ); \
	( algoIDInfo )->algoInfo = ( algoStrInfo ); \
	( algoIDInfo )->preferredAlgo = ( prefAlgo ); \
	( algoIDInfo )->getAlgoType = ( getType ); \
	}

static int getAlgoIDEx( ALGOID_INFO *algoIDInfo, const BYTE *string, 
						const int maxLength, void *errorInfo )
	{
	int stringPos = 0, stringLen, algoIndex = 999;

	assert( isWritePtr( algoIDInfo, sizeof( ALGOID_INFO ) ) );
	assert( isReadPtr( algoIDInfo->algoInfo, sizeof( ALGO_STRING_INFO ) ) );
	assert( isReadPtr( string, maxLength ) );
	assert( maxLength > LENGTH_SIZE );
	assert( ( algoIDInfo->getAlgoType == GETALGO_BEST_MATCH && \
			  algoIDInfo->preferredAlgo == CRYPT_ALGO_NONE ) || \
			( algoIDInfo->getAlgoType == GETALGO_FIRST_MATCH ) ||
			( algoIDInfo->getAlgoType == GETALGO_FIRST_MATCH_WARN && \
			  ( algoIDInfo->preferredAlgo > CRYPT_ALGO_NONE && \
				algoIDInfo->preferredAlgo < CRYPT_ALGO_LAST ) ) );

	/* Get the string length and make sure that it's valid */
	if( maxLength < LENGTH_SIZE + SSH2_MIN_ALGOID_SIZE )
		retExt( errorInfo, CRYPT_ERROR_BADDATA,
				"Invalid minimum algorithm ID size %d", maxLength );
	stringLen = mgetLong( string );
	if( stringLen <= 0 || stringLen > maxLength - LENGTH_SIZE )
		retExt( errorInfo, CRYPT_ERROR_BADDATA,
				"Invalid algorithm ID string size %d", stringLen );

	/* Walk down the string looking for a recognised algorithm.  Since our
	   preference may not match the other side's preferences, we have to walk
	   down the entire list to find our preferred choice */
	while( stringPos < stringLen )
		{
		int len, i;

		/* Find the length of the next algorithm name */
		for( len = stringPos; len < stringLen && string[ len ] != ','; len++ );
		len -= stringPos;
		if( len < SSH2_MIN_ALGOID_SIZE )
			{
			/* Empty or too-short algorithm name, continue */
			stringPos += len + 1;
			continue;
			}

		/* Check whether it's something that we can handle */
		for( i = 0; algoIDInfo->algoInfo[ i ].name != NULL; i++ )
			if( len == strlen( algoIDInfo->algoInfo[ i ].name ) && \
				!memcmp( algoIDInfo->algoInfo[ i ].name, 
						 string + stringPos, len ) )
				break;
		if( algoIDInfo->algoInfo[ i ].name == NULL || \
			!algoAvailable( algoIDInfo->algoInfo[ i ].algo ) )
			{
			/* No match or the matched algorithm isn't available in this 
			   build, if we have to match the first algorithm on the list
			   remember to warn the caller, then move on to the next name */
			if( algoIDInfo->getAlgoType == GETALGO_FIRST_MATCH_WARN )
				algoIDInfo->prefAlgoMismatch = TRUE;
			stringPos += len + 1;
			continue;
			}

		switch( algoIDInfo->getAlgoType )
			{
			case GETALGO_BEST_MATCH:
				/* If we're looking for the best (highest-ranked algorithm) 
				   match, see whether the current match ranks higher than 
				   the existing one */
				if( i < algoIndex )
					{
					algoIndex = i;
					if( algoIndex <= 0 )
						/* Gruener werd's net */
						stringPos = stringLen;	/* Force outer loop exit */
					}
				break;

			case GETALGO_FIRST_MATCH:
				/* If we've found an acceptable algorithm, remember it and 
				   exit */
				if( algoIDInfo->preferredAlgo == CRYPT_ALGO_NONE || \
					algoIDInfo->preferredAlgo == algoIDInfo->algoInfo[ i ].algo )
					{
					algoIndex = i;
					stringPos = stringLen;	/* Force outer loop exit */
					}
				break;

			case GETALGO_FIRST_MATCH_WARN:
				/* If we found the algorithm that we're after, remember it 
				   and exit */
				if( algoIDInfo->preferredAlgo != algoIDInfo->algoInfo[ i ].algo )
					/* We didn't match the first algorithm on the list, warn 
					   the caller */
					algoIDInfo->prefAlgoMismatch = TRUE;
				algoIndex = i;
				stringPos = stringLen;		/* Force outer loop exit */
				break;

			default:
				assert( NOTREACHED );
			}

		/* Check the next name */
		stringPos += len + 1;
		}
	if( algoIndex == 999 )
		/* We couldn't find anything to use */
		retExt( errorInfo, CRYPT_ERROR_NOTAVAIL,
				"No crypto algorithm compatible with the remote system was "
				"found" );

	/* We found a more-preferred algorithm than the default, go with that */
	algoIDInfo->algo = algoIDInfo->algoInfo[ algoIndex ].algo;
	algoIDInfo->algoStringLength = LENGTH_SIZE + stringLen;
	return( CRYPT_OK );
	}

int getAlgoID( const ALGO_STRING_INFO *algoInfo, CRYPT_ALGO_TYPE *algo, 
			   const CRYPT_ALGO_TYPE preferredAlgo, const BYTE *string, 
			   const int maxLength, void *errorInfo )
	{
	ALGOID_INFO algoIDInfo;
	int status;

	setAlgoIDInfo( &algoIDInfo, algoInfo, preferredAlgo, 
				   GETALGO_FIRST_MATCH );
	status = getAlgoIDEx( &algoIDInfo, string, maxLength, errorInfo );
	if( cryptStatusOK( status ) && algo != NULL )
		*algo = algoIDInfo.algo;
	return( cryptStatusError( status ) ? \
			status : algoIDInfo.algoStringLength );
	}

/* Algorithms used to protect data packets are used in pairs, one for 
   incoming and the other for outgoing data.  To keep things simple we 
   always force these to be the same, first reading the algorithm for one 
   direction and then making sure that the one for the other direction 
   matches this.  All implementations seem to do this anyway, many aren't 
   even capable of supporting asymmetric algorithm choices */

static int getAlgoIDpair( const ALGO_STRING_INFO *algoInfo, 
						  CRYPT_ALGO_TYPE *algo, const BYTE *string, 
						  const int maxLength, const BOOLEAN isServer, 
						  void *errorInfo )
	{
	CRYPT_ALGO_TYPE pairPreferredAlgo;
	ALGOID_INFO algoIDInfo;
	int length, status;

	assert( isReadPtr( algoInfo, sizeof( ALGO_STRING_INFO ) ) );
	assert( isReadPtr( string, maxLength ) );

	/* Clear return value */
	if( algo != NULL )
		*algo = CRYPT_ALGO_NONE;

	/* Make sure the input parameters are in order */
	if( maxLength < ( LENGTH_SIZE + SSH2_MIN_ALGOID_SIZE ) * 2 )
		retExt( errorInfo, CRYPT_ERROR_BADDATA,
				"Invalid minimum algorithm ID pair size %d", maxLength );

	/* Get the first algorithm */
	setAlgoIDInfo( &algoIDInfo, algoInfo, CRYPT_ALGO_NONE,
				   isServer ? GETALGO_FIRST_MATCH : GETALGO_BEST_MATCH );
	status = getAlgoIDEx( &algoIDInfo, string, maxLength, errorInfo );
	if( cryptStatusError( status ) )
		return( status );
	pairPreferredAlgo = algoIDInfo.algo;
	length = algoIDInfo.algoStringLength;

	/* Get the matched seconed algorithm */
	setAlgoIDInfo( &algoIDInfo, algoInfo, pairPreferredAlgo, 
				   GETALGO_FIRST_MATCH );
	status = getAlgoIDEx( &algoIDInfo, string + length, maxLength - length,
						  errorInfo );
	if( pairPreferredAlgo != algoIDInfo.algo )
		retExt( errorInfo, CRYPT_ERROR_BADDATA,
				"Client algorithm %d doesn't match server algorithm %d in "
				"algorithm pair", pairPreferredAlgo, algoIDInfo.algo );
	if( algo != NULL )
		*algo = algoIDInfo.algo;
	return( cryptStatusError( status ) ? \
			status : length + algoIDInfo.algoStringLength );
	}

/* Convert a cryptlib algorithm ID to an SSHv2 algorithm name */

int putAlgoID( BYTE **bufPtrPtr, const CRYPT_ALGO_TYPE algo )
	{
	static const FAR_BSS ALGO_STRING_INFO algoStringMapTbl[] = {
		{ "ssh-rsa", CRYPT_ALGO_RSA },
		{ "ssh-dss", CRYPT_ALGO_DSA },
		{ "3des-cbc", CRYPT_ALGO_3DES },
		{ "aes128-cbc", CRYPT_ALGO_AES },
		{ "blowfish-cbc", CRYPT_ALGO_BLOWFISH },
		{ "cast128-cbc", CRYPT_ALGO_CAST },
		{ "idea-cbc", CRYPT_ALGO_IDEA },
		{ "arcfour", CRYPT_ALGO_RC4 },
		{ "diffie-hellman-group1-sha1", CRYPT_ALGO_DH },
		{ "hmac-sha1", CRYPT_ALGO_HMAC_SHA },
		{ "hmac-md5", CRYPT_ALGO_HMAC_MD5 },
		{ "none", CRYPT_ALGO_NONE },
		{ "none", CRYPT_ALGO_LAST }		/* Catch-all */
		};
	int length, i;

	/* Locate the name for this algorithm and encode it as an SSH string */
	for( i = 0; algoStringMapTbl[ i ].algo != CRYPT_ALGO_LAST && \
				algoStringMapTbl[ i ].algo != algo; i++ );
	assert( algoStringMapTbl[ i ].algo != CRYPT_ALGO_LAST );
	length = strlen( algoStringMapTbl[ i ].name );
	if( bufPtrPtr != NULL )
		{
		BYTE *bufPtr = *bufPtrPtr;

		mputLong( bufPtr, length );
		memcpy( bufPtr, algoStringMapTbl[ i ].name, length );
		*bufPtrPtr += LENGTH_SIZE + length;
		}
	return( LENGTH_SIZE + length );
	}

/* Encode/decode a value as an SSHv2 MPI.  The decoded value is always the
   DH keyex MPI, so we can perform some special-case checks on it */

int encodeMPI( BYTE *buffer, const BYTE *value,
			   const int valueLength )
	{
	BYTE *bufPtr = buffer;
	const int mpiValueLength = valueLength + \
							   ( ( value[ 0 ] & 0x80 ) ? 1 : 0 );

	if( buffer != NULL )
		{
		mputLong( bufPtr, mpiValueLength );
		if( value[ 0 ] & 0x80 )
			*bufPtr++ = 0;	/* MPIs are signed values */
		memcpy( bufPtr, value, valueLength );
		}
	return( LENGTH_SIZE + mpiValueLength );
	}

static int readKeyexMPI( SESSION_INFO *sessionInfoPtr, BYTE *value,
						 const BYTE *bufPtr, const int nominalLength )
	{
	int length;

	if( bufPtr[ 0 ] || bufPtr[ 1 ] || \
		( bufPtr[ 2 ] & ~( ( CRYPT_MAX_PKCSIZE << 1 ) - 1 ) ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid MPI length header 0x%02X 0x%02X 0x%02X 0x%02X", 
				bufPtr[ 0 ], bufPtr[ 1 ], bufPtr[ 2 ], bufPtr[ 3 ] );
	length = ( ( int ) bufPtr[ 2 ] << 8 ) | bufPtr[ 3 ];
	if( length < nominalLength - 8 || length > nominalLength + 1 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid MPI length %d, nominal length is %d", length,
				nominalLength );
	bufPtr += LENGTH_SIZE;
	while( !*bufPtr && length > 1 )
		{
		/* Strip leading zero padding */
		bufPtr++;
		length--;
		}
	if( length < nominalLength - 8 || length > nominalLength )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid normalised MPI length %d, nominal length is %d",
				length, nominalLength );
	memcpy( value, bufPtr, length );
	return( length );
	}

/* Hash a value encoded as an SSH string and as an MPI */

int hashAsString( const CRYPT_CONTEXT iHashContext,
				  const BYTE *data, const int dataLength )
	{
	BYTE buffer[ 128 ], *bufPtr = buffer;
	int status;

	/* Prepend the string length to the data and hash it.  If it'll fit into
	   the buffer we copy it over to save a kernel call */
	mputLong( bufPtr, dataLength );
	if( dataLength <= 128 - LENGTH_SIZE )
		{
		memcpy( buffer + LENGTH_SIZE, data, dataLength );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
								  LENGTH_SIZE + dataLength );
		}
	else
		{
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
						 LENGTH_SIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  ( void * ) data, dataLength );
		}
	zeroise( buffer, 128 );

	return( status );
	}

int hashAsMPI( const CRYPT_CONTEXT iHashContext, const BYTE *data, 
			   const int dataLength )
	{
	BYTE buffer[ 8 ], *bufPtr = buffer;
	const int length = ( data[ 0 ] & 0x80 ) ? dataLength + 1 : dataLength;
	int headerLength = LENGTH_SIZE;

	/* Prepend the MPI length to the data and hash it.  Since this is often
	   sensitive data, we don't take a local copy but hash it in two parts */
	mputLong( bufPtr, length );
	if( data[ 0 ] & 0x80 )
		{
		/* MPIs are signed values */
		*bufPtr++ = 0;
		headerLength++;
		}
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, headerLength );
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
							  ( void * ) data, dataLength ) );
	}

/* Complete the hashing necessary to generate a cryptovariable and send it
   to a context */

static int loadCryptovariable( const CRYPT_CONTEXT iCryptContext,
							   const CRYPT_ATTRIBUTE_TYPE attribute,
							   const int attributeSize, HASHFUNCTION hashFunction,
							   const HASHINFO initialHashInfo, const BYTE *nonce,
							   const BYTE *data, const int dataLen )
	{
	RESOURCE_DATA msgData;
	HASHINFO hashInfo;
	BYTE buffer[ CRYPT_MAX_KEYSIZE ];
	int status;

	/* Complete the hashing */
	memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
	if( nonce != NULL )
		hashFunction( hashInfo, NULL, nonce, 1, HASH_CONTINUE );
	hashFunction( hashInfo, buffer, data, dataLen, HASH_END );
	if( attributeSize > 20 )
		{
		/* If we need more data than the hashing will provide in one go,
		   generate a second block as:

			hash( shared_secret || exchange_hash || data )

		   where the shared secret and exchange hash are present as the
		   precomputed data in the initial hash info and the data part is
		   the output of the hash step above */
		memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
		hashFunction( hashInfo, buffer + 20, buffer, 20, HASH_END );
		}
	zeroise( hashInfo, sizeof( HASHINFO ) );

	/* Send the data to the context */
	setMessageData( &msgData, buffer, attributeSize );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, attribute );
	zeroise( buffer, CRYPT_MAX_KEYSIZE );

	return( status );
	}

/* Set up the security information required for the session */

int initSecurityInfo( SESSION_INFO *sessionInfoPtr,
					  SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	HASHFUNCTION hashFunction;
	HASHINFO initialHashInfo;
	const BOOLEAN isClient = \
				( sessionInfoPtr->flags & SESSION_ISSERVER ) ? FALSE : TRUE;
	const int mpiLength = handshakeInfo->secretValueLength + \
				( ( handshakeInfo->secretValue[ 0 ] & 0x80 ) ? 1 : 0 );
	int keySize, ivSize, status;

	/* Create the security contexts required for the session */
	status = initSecurityContexts( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_BLOWFISH )
		/* Blowfish has a variable-length key so we have to explicitly
		   specify its length */
		keySize = SSH2_FIXED_KEY_SIZE;
	else
		krnlSendMessage( sessionInfoPtr->iCryptInContext,
						 IMESSAGE_GETATTRIBUTE, &keySize,
						 CRYPT_CTXINFO_KEYSIZE );
	if( krnlSendMessage( sessionInfoPtr->iCryptInContext,
						 IMESSAGE_GETATTRIBUTE, &ivSize,
						 CRYPT_CTXINFO_IVSIZE ) == CRYPT_ERROR_NOTAVAIL )
		/* It's a stream cipher */
		ivSize = 0;

	/* Get the hash algorithm information and pre-hash the shared secret and
	   exchange hash, which are reused for all cryptovariables.  The overall
	   hashing is:

		hash( MPI( shared_secret ) || exchange_hash || \
			  nonce || exchange_hash )

	   Note the apparently redundant double hashing of the exchange hash, 
	   this is required because the spec refers to it by two different names,
	   the exchange hash and the session ID, and then requires that both be
	   hashed (actually it's a bit more complex than that, with issues 
	   related to re-keying, but for now it acts as a re-hash of the same
	   data).

	   Before we can hash the shared secret we have to convert it into MPI
	   form, which we do by generating a pseudo-header and hashing that
	   separately.  The nonce is "A", "B", "C", ... */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
	if( ( sessionInfoPtr->protocolFlags & SSH_PFLAG_NOHASHSECRET ) )
		{
		/* Some implementations erroneously omit the shared secret when
		   creating the keying material.  This is suboptimal but not fatal,
		   since the shared secret is also hashed into the exchange hash */
		hashFunction( initialHashInfo, NULL, handshakeInfo->sessionID,
					  handshakeInfo->sessionIDlength, HASH_START );
		}
	else
		{
		BYTE header[ 8 ], *headerPtr = header;

		mputLong( headerPtr, mpiLength );
		if( handshakeInfo->secretValue[ 0 ] & 0x80 )
			*headerPtr++ = 0;
		hashFunction( initialHashInfo, NULL, header, headerPtr - header,
					  HASH_START );
		hashFunction( initialHashInfo, NULL, handshakeInfo->secretValue,
					  handshakeInfo->secretValueLength, HASH_CONTINUE );
		hashFunction( initialHashInfo, NULL, handshakeInfo->sessionID,
					  handshakeInfo->sessionIDlength, HASH_CONTINUE );
		}

	/* Load the cryptovariables.  The order is:

		client_write_iv, server_write_iv
		client_write_key, server_write_key
		client_write_mac, server_write_mac

	   Although HMAC has a variable-length key and should therefore follow
	   the SSH2_FIXED_KEY_SIZE rule, the key size was in later RFC drafts
	   set to the HMAC block size.  Some implementations erroneously used 
	   the fixed-size key, so we adjust the HMAC key size if we're talking
	   to one of these */
	if( !isStreamCipher( sessionInfoPtr->cryptAlgo ) )
		{
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iCryptOutContext : \
										sessionInfoPtr->iCryptInContext,
									 CRYPT_CTXINFO_IV, ivSize,
									 hashFunction, initialHashInfo, "A",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
		if( cryptStatusOK( status ) )
			status = loadCryptovariable( isClient ? \
											sessionInfoPtr->iCryptInContext : \
											sessionInfoPtr->iCryptOutContext,
										 CRYPT_CTXINFO_IV, ivSize,
										 hashFunction, initialHashInfo, "B",
										 handshakeInfo->sessionID,
										 handshakeInfo->sessionIDlength );
		}
	if( cryptStatusOK( status ) )
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iCryptOutContext : \
										sessionInfoPtr->iCryptInContext,
									 CRYPT_CTXINFO_KEY, keySize,
									 hashFunction, initialHashInfo, "C",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
	if( cryptStatusOK( status ) )
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iCryptInContext : \
										sessionInfoPtr->iCryptOutContext,
									 CRYPT_CTXINFO_KEY, keySize,
									 hashFunction, initialHashInfo, "D",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
	if( cryptStatusOK( status ) )
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iAuthOutContext : \
										sessionInfoPtr->iAuthInContext,
									 CRYPT_CTXINFO_KEY,
									 ( sessionInfoPtr->protocolFlags & \
									   SSH_PFLAG_HMACKEYSIZE ) ? \
										SSH2_FIXED_KEY_SIZE : \
										sessionInfoPtr->authBlocksize,
									 hashFunction, initialHashInfo, "E",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
	if( cryptStatusOK( status ) )
		status = loadCryptovariable( isClient ? \
										sessionInfoPtr->iAuthInContext : \
										sessionInfoPtr->iAuthOutContext,
									 CRYPT_CTXINFO_KEY,
									 ( sessionInfoPtr->protocolFlags & \
									   SSH_PFLAG_HMACKEYSIZE ) ? \
										SSH2_FIXED_KEY_SIZE : \
										sessionInfoPtr->authBlocksize,
									 hashFunction, initialHashInfo, "F",
									 handshakeInfo->sessionID,
									 handshakeInfo->sessionIDlength );
	return( status );
	}

/* MAC the payload of a data packet.  Since we may not have the whole packet
   available at once, we can do this in one go or incrementally */

typedef enum { MAC_START, MAC_END, MAC_ALL } MAC_TYPE;

static BOOLEAN macPayload( const CRYPT_CONTEXT iMacContext,
						   const long seqNo, const BYTE *data,
						   const int dataLength, const int packetDataLength,
						   const MAC_TYPE macType )
	{
	int status;

	/* MAC the data and compare the result to the stored MAC:

		HMAC( seqNo || length || payload )

	   During the handshake process we have the entire packet at hand 
	   (dataLength == packetDataLength) and can process it at once.  When 
	   we're processing payload data (dataLength a subset of 
	   packetDataLength) we have to process the header separately in order 
	   to determine how much more we have to read, so we have to MAC the 
	   packet in two parts */
	if( macType == MAC_START || macType == MAC_ALL )
		{
		BYTE buffer[ 16 ], *bufPtr = buffer;
		int length = ( macType == MAC_ALL ) ? dataLength : packetDataLength;

		assert( ( macType == MAC_ALL && packetDataLength == 0 ) || \
				( macType == MAC_START && packetDataLength >= dataLength ) );

		/* Since the payload had the length stripped during the speculative
		   read, we have to reconstruct it and hash it separately before we
		   hash the data.  If we're doing the hash in parts, the amount of
		   data being hashed won't match the overall length so the caller
		   needs to supply the overall packet length, as well as the current 
		   data length */
		mputLong( bufPtr, seqNo );
		mputLong( bufPtr, length );
		krnlSendMessage( iMacContext, IMESSAGE_DELETEATTRIBUTE, NULL,
						 CRYPT_CTXINFO_HASHVALUE );
		krnlSendMessage( iMacContext, IMESSAGE_CTX_HASH, buffer,
						 LENGTH_SIZE + LENGTH_SIZE );
		}
	krnlSendMessage( iMacContext, IMESSAGE_CTX_HASH, ( void * ) data,
					 dataLength );
	if( macType == MAC_END || macType == MAC_ALL )
		{
		RESOURCE_DATA msgData;
		BYTE macBuffer[ CRYPT_MAX_HASHSIZE ];

		krnlSendMessage( iMacContext, IMESSAGE_CTX_HASH, "", 0 );
		setMessageData( &msgData, macBuffer, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iMacContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusError( status ) || \
			memcmp( macBuffer, data + dataLength, msgData.length ) )
			return( FALSE );
		}

	return( TRUE );
	}

/* Get the reason why the peer closed the connection */

static int getDisconnectInfo( SESSION_INFO *sessionInfoPtr, BYTE *bufPtr )
	{
	static const FAR_BSS struct {
		const int sshStatus, cryptlibStatus;
		} errorMap[] = {
		{ SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT, CRYPT_ERROR_PERMISSION },
		{ SSH2_DISCONNECT_MAC_ERROR, CRYPT_ERROR_SIGNATURE },
		{ SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, CRYPT_ERROR_NOTAVAIL },
		{ SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, CRYPT_ERROR_NOTAVAIL },
		{ SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, CRYPT_ERROR_WRONGKEY },
		{ CRYPT_ERROR, CRYPT_ERROR_READ }
		};
	int length, i;

	/* Server is disconnecting, find out why */
	bufPtr++;				/* Skip packet type */
	sessionInfoPtr->errorCode = mgetLong( bufPtr );
	length = mgetLong( bufPtr );
	if( length < 0 || length > MAX_ERRMSG_SIZE - 32 )
		retExt( sessionInfoPtr, CRYPT_ERROR_OVERFLOW,
				"Invalid error information size %d", length );
	strcpy( sessionInfoPtr->errorMessage, "Received SSHv2 server message: " );
	if( length <= 0 )
		strcat( sessionInfoPtr->errorMessage, "<None>" );
	else
		{
		memcpy( sessionInfoPtr->errorMessage + 31, bufPtr, length );
		sessionInfoPtr->errorMessage[ 31 + length ] = '\0';
		}

	/* Try and map the SSH status to an equivalent cryptlib code */
	for( i = 0; errorMap[ i ].sshStatus != CRYPT_ERROR; i++ )
		if( errorMap[ i ].sshStatus == sessionInfoPtr->errorCode )
			break;
	return( errorMap[ i ].cryptlibStatus );
	}

/* Read an SSHv2 packet.  This function is only used during the handshake 
   phase (the data transfer phase has its own read/write code) so we can
   perform some special-case handling based on this */

int readPacketSSH2( SESSION_INFO *sessionInfoPtr, int expectedType )
	{
	BYTE *dataStartPtr;
	long length;
	int padLength = 0, packetType;

	/* Alongside the expected packets the server can send us all sorts of
	   no-op messages, ranging from explicit no-ops (SSH2_MSG_IGNORE) through
	   to general chattiness (SSH2_MSG_DEBUG, SSH2_MSG_USERAUTH_BANNER).
	   Because we can receive any quantity of these at any time, we have to
	   run the receive code in a loop to strip them out */
	do
		{
		BYTE *bufPtr = sessionInfoPtr->receiveBuffer;
		int extraLength = 0, status;

		/* Read the SSHv2 packet header:

			uint32		length
			byte		padLen
		  [	byte		type - checked but not removed ]
			byte[]		data
			byte[]		padding
			byte[]		MAC

		  The reason why the length and pad length precede the packet type
		  and other information is that these two fields are part of the
		  SSHv2 transport layer while the type and payload are seen as part
		  of the connection layer, although the different RFCs tend to mix 
		  them up quite thoroughly.

		  SSHv2 encrypts everything (including the length) so we need to
		  speculatively read ahead for the minimum packet size and decrypt
		  that in order to figure out what to do */
		assert( sessionInfoPtr->receiveBufEnd == 0 );
		status = readFixedHeader( sessionInfoPtr, MIN_PACKET_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		assert( status == MIN_PACKET_SIZE );
		if( ( sessionInfoPtr->protocolFlags & SSH_PFLAG_TEXTDIAGS ) && \
			sessionInfoPtr->receiveBuffer[ 0 ] == 'F' && \
			( !memcmp( sessionInfoPtr->receiveBuffer, "FATAL: ", 7 ) || \
			  !memcmp( sessionInfoPtr->receiveBuffer, "FATAL ERROR:", 12 ) ) )
			{
			/* Versions of SSH derived from the original SSH code base can
			   sometimes dump raw text strings (that is, strings not 
			   encapsulated in SSH packets such as error packets) onto the 
			   connection if something unexpected occurs.  Normally this 
			   would result in a bad data or MAC error since they decrypt to
			   garbage, so we try and catch them here */
			dataStartPtr = sessionInfoPtr->receiveBuffer + MIN_PACKET_SIZE;
			for( length = 0; 
				 length < MAX_ERRMSG_SIZE - ( MIN_PACKET_SIZE + 64 ); 
				 length++ )
				{
				status = sread( &sessionInfoPtr->stream, 
								dataStartPtr + length, 1 );
				if( cryptStatusError( status ) || \
					dataStartPtr[ length ] == '\n' )
					break;
				}
			while( length > 0 && \
				   ( dataStartPtr[ length - 1 ] == '\r' || \
				     dataStartPtr[ length - 1 ] == '\n' ) )
				length--;
			dataStartPtr[ length ] = '\0';

			/* Report the error as a problem with the remote software.  
			   Since the other side has bailed out, we mark the channel as 
			   closed to prevent any attempt to perform proper shutdown */
			sessionInfoPtr->flags |= SESSION_SENDCLOSED;
			sessionInfoPtr->protocolFlags |= SSH_PFLAG_CHANNELCLOSED;
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Remote SSH software has crashed, diagnostic was '%s'",
					sessionInfoPtr->receiveBuffer );
			}
		if( sessionInfoPtr->flags & SESSION_ISSECURE )
			{
			status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
									  IMESSAGE_CTX_DECRYPT,
									  sessionInfoPtr->receiveBuffer,
									  MIN_PACKET_SIZE );
			if( cryptStatusError( status ) )
				return( status );
			}
		length = mgetLong( bufPtr );
		assert( SSH2_HEADER_REMAINDER_SIZE == MIN_PACKET_SIZE - LENGTH_SIZE );
		if( sessionInfoPtr->flags & SESSION_ISSECURE )
			/* The MAC size isn't included in the packet length so we have to
			   add it manually */
			extraLength = sessionInfoPtr->authBlocksize;
		if( length + extraLength < SSH2_HEADER_REMAINDER_SIZE || \
			length + extraLength >= sessionInfoPtr->receiveBufSize )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid packet length %d, extra length %d", length,
					extraLength );
		memmove( sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBuffer + LENGTH_SIZE,
				 SSH2_HEADER_REMAINDER_SIZE );
		if( length + extraLength > SSH2_HEADER_REMAINDER_SIZE )
			{
			const long remainingLength = length + extraLength - \
										 SSH2_HEADER_REMAINDER_SIZE;

			/* The change cipherspec message has length 0, so we only
			   perform the read if there's packet data present.  Because
			   this code is called conditionally, we can't make the read
			   part of the fixed-header read but have to do independent
			   handling of shortfalls due to read timeouts */
			status = sread( &sessionInfoPtr->stream,
							sessionInfoPtr->receiveBuffer + \
								SSH2_HEADER_REMAINDER_SIZE,
							remainingLength );
			if( cryptStatusError( status ) )
				{
				sNetGetErrorInfo( &sessionInfoPtr->stream,
								  sessionInfoPtr->errorMessage,
								  &sessionInfoPtr->errorCode );
				return( status );
				}
			if( status != remainingLength )
				retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT,
						"Timeout during packet remainder read, only got %d "
						"of %d bytes", status, remainingLength );
			}
		if( sessionInfoPtr->flags & SESSION_ISSECURE )
			{
			/* Decrypt the remainder of the packet except for the MAC */
			status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
									  IMESSAGE_CTX_DECRYPT,
									  sessionInfoPtr->receiveBuffer + \
										SSH2_HEADER_REMAINDER_SIZE,
									  length - SSH2_HEADER_REMAINDER_SIZE );
			if( cryptStatusError( status ) )
				return( status );

			/* MAC the decrypted payload */
			if( !macPayload( sessionInfoPtr->iAuthInContext,
							 sessionInfoPtr->readSeqNo,
							 sessionInfoPtr->receiveBuffer, length, 0,
							 MAC_ALL ) )
				{
				/* If we're expecting a service control packet after a change
				   cipherspec packet and don't get it then it's more likely
				   that the problem is due to the wrong key being used than
				   data corruption, so we return a wrong key error instead
				   of bad data */
				if( expectedType == SSH2_MSG_SERVICE_REQUEST || \
					expectedType == SSH2_MSG_SERVICE_ACCEPT )
					retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
							"Bad message MAC, probably due to an incorrect "
							"key being used to generate the MAC" );
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Bad message MAC" );
				}
			}
		padLength = sessionInfoPtr->receiveBuffer[ 0 ];
		packetType = sessionInfoPtr->receiveBuffer[ 1 ];
		sessionInfoPtr->readSeqNo++;
		}
	while( packetType == SSH2_MSG_IGNORE || packetType == SSH2_MSG_DEBUG || \
		   packetType == SSH2_MSG_USERAUTH_BANNER );
	sessionInfoPtr->sshPacketType = packetType;

	/* Adjust the length to account for the fixed-size fields and remember
	   where the data starts */
	dataStartPtr = sessionInfoPtr->receiveBuffer + PADLENGTH_SIZE;
	length -= PADLENGTH_SIZE + padLength;

	/* Make sure that we either got what we asked for or one of the allowed
	   special-case packets */
	if( packetType == SSH2_MSG_DISCONNECT )
		return( getDisconnectInfo( sessionInfoPtr, dataStartPtr ) );
	if( expectedType == SSH2_MSG_SPECIAL_USERAUTH )
		{
		/* If we're reading a response to a user authentication message then
		   getting a failure response is valid (even if it's not what we're
		   expecting) since it's an indication that an incorrect password was
		   used rather than that there was some general type of failure:

			byte	type = SSH2_MSG_USERAUTH_FAILURE
			string	allowed_authent
			boolean	partial_success = FALSE */
		if( packetType == SSH2_MSG_USERAUTH_FAILURE )
			{
			BYTE *bufPtr = dataStartPtr;
			long stringLength;

			if( length < ID_SIZE + ( LENGTH_SIZE + 1 ) + BOOLEAN_SIZE )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid user auth response length %d", length );
			bufPtr++;		/* Skip packet type */
			stringLength = mgetLong( bufPtr );
			if( length != ID_SIZE + LENGTH_SIZE + stringLength + BOOLEAN_SIZE )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid user auth response length %d, string length "
						"%d", length, stringLength );

			/* If the returned information can fit into an error message,
			   return it to the caller */
			if( stringLength < MAX_ERRMSG_SIZE - 70 )
				{
				strcpy( sessionInfoPtr->errorMessage,
						"Received SSHv2 server message: Permitted "
						"authentication types are " );
				memcpy( sessionInfoPtr->errorMessage + 66, bufPtr, 
						stringLength );
				sessionInfoPtr->errorMessage[ 66 + stringLength ] = '\0';
				}
			memmove( sessionInfoPtr->receiveBuffer, dataStartPtr, length );
			return( CRYPT_ERROR_WRONGKEY );
			}
		expectedType = SSH2_MSG_USERAUTH_SUCCESS;
		}
	if( expectedType == SSH2_MSG_SPECIAL_REQUEST )
		{
		/* If we're at the end of the handshake phase we can get either a 
		   global or a channel request to tell us what to do next */
		if( packetType != SSH2_MSG_GLOBAL_REQUEST && \
			packetType != SSH2_MSG_CHANNEL_REQUEST )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid packet type %d, expected global or channel "
					"request", packetType );
		expectedType = packetType;
		}
	if( expectedType == SSH2_MSG_KEXDH_GEX_REQUEST && \
		packetType == SSH2_MSG_KEXDH_GEX_REQUEST_NEW )
		/* The ephemeral DH key exchange spec was changed halfway through to
		   try and work around problems with key negotiation, because of this
		   we can see two different types of ephemeral DH request, although
		   they're functionally identical */
		expectedType = packetType;
	if( packetType != expectedType )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet type %d, expected %d", packetType,
				expectedType );

	/* Move the data down in the buffer to get rid of the header info,
	   and discard the padding.  This isn't as inefficient as it seems
	   since it's only used for the short handshake messages */
	memmove( sessionInfoPtr->receiveBuffer, dataStartPtr, length );
	return( length );
	}

/* Send an SSHv2 packet.  During the handshake phase we may be sending
   multiple packets at once, however unlike SSL, SSH requires that each
   packet in a multi-packet group be individually wrapped so we have to
   provide a facility for separately wrapping and sending packets to handle
   this */

int wrapPacket( SESSION_INFO *sessionInfoPtr, BYTE *bufPtr,
				const int dataLength )
	{
	const BYTE *bufStartPtr = bufPtr;
	const int length = LENGTH_SIZE + PADLENGTH_SIZE + dataLength;
	const int padBlockSize = max( sessionInfoPtr->cryptBlocksize, 8 );
	int padLength, status;

	/* Evaludate the number of padding bytes that we need to add to a packet 
	   to make it a multiple of the cipher block size long, with a minimum 
	   padding size of SSH2_MIN_PADLENGTH_SIZE bytes.  Note that this padding 
	   is required even when there's no encryption being applied, although we 
	   set the padding to all zeroes in this case */
	if( bufPtr[ LENGTH_SIZE + PADLENGTH_SIZE ] == SSH2_MSG_USERAUTH_REQUEST )
		{
		/* It's a user-authentication packet that (probably) contains a
		   password, make it fixed-length to hide the length information */
		for( padLength = 256; 
			 ( length + SSH2_MIN_PADLENGTH_SIZE ) > padLength; 
			 padLength += 256 );
		padLength -= length;
		}
	else
		padLength = roundUp( length + SSH2_MIN_PADLENGTH_SIZE, 
							 padBlockSize ) - length;
	assert( padLength >= SSH2_MIN_PADLENGTH_SIZE && padLength < 256 );

	/* Add the SSH packet header:

		uint32		length
		byte		padLen
		byte[]		data
		byte[]		padding
		byte[]		MAC */
	mputLong( bufPtr, ( long ) ( length - LENGTH_SIZE ) + padLength );
	*bufPtr++ = padLength;
	bufPtr += dataLength;
	if( sessionInfoPtr->flags & SESSION_ISSECURE )
		{
		RESOURCE_DATA msgData;
		BYTE seqBuffer[ 8 ], *seqBufPtr = seqBuffer;
		const int payloadLength = SSH2_HEADER_SIZE + dataLength + padLength;

		/* Append the padding */
		setMessageData( &msgData, bufPtr, padLength );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		bufPtr += padLength;
		assert( bufPtr == bufStartPtr + payloadLength );

		/* MAC the data:

			HMAC( seqNo || payload ) */
		mputLong( seqBufPtr, sessionInfoPtr->writeSeqNo );
		krnlSendMessage( sessionInfoPtr->iAuthOutContext,
						 IMESSAGE_DELETEATTRIBUTE, NULL,
						 CRYPT_CTXINFO_HASHVALUE );
		krnlSendMessage( sessionInfoPtr->iAuthOutContext,
						 IMESSAGE_CTX_HASH, seqBuffer, LENGTH_SIZE );
		krnlSendMessage( sessionInfoPtr->iAuthOutContext,
						 IMESSAGE_CTX_HASH, ( void * ) bufStartPtr,
						 payloadLength );
		krnlSendMessage( sessionInfoPtr->iAuthOutContext,
						 IMESSAGE_CTX_HASH, "", 0 );
		setMessageData( &msgData, bufPtr, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( sessionInfoPtr->iAuthOutContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusError( status ) )
			return( status );

		/* Encrypt the entire packet except for the MAC */
		status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
								  IMESSAGE_CTX_ENCRYPT, ( void * ) bufStartPtr,
								  payloadLength );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		/* If there's no security in effect yet, the padding is all zeroes */
		memset( bufPtr, 0, padLength );
	sessionInfoPtr->writeSeqNo++;

	return( SSH2_HEADER_SIZE + dataLength + padLength + \
			( ( sessionInfoPtr->flags & SESSION_ISSECURE ) ? \
			  sessionInfoPtr->authBlocksize : 0 ) );
	}

int sendPacketSSH2( SESSION_INFO *sessionInfoPtr, const int dataLength,
					const BOOLEAN sendOnly )
	{
	int length = dataLength, status;

	if( !sendOnly )
		{
		length = wrapPacket( sessionInfoPtr, sessionInfoPtr->sendBuffer,
							 dataLength );
		if( cryptStatusError( length ) )
			return( length );
		}
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->sendBuffer, 
					 length );
	if( cryptStatusError( status ) )
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
	return( CRYPT_OK );
	}

/* Process a client/server hello packet */

int processHello( SESSION_INFO *sessionInfoPtr, 
				  SSH_HANDSHAKE_INFO *handshakeInfo, int *keyexLength,
				  const BOOLEAN isServer )
	{
	ALGOID_INFO algoIDInfo;
	BYTE *bufPtr;
	BOOLEAN preferredAlgoMismatch = FALSE;
	int length, stringLength, status;

	/* Process the client/server hello:

		byte		type = SSH2_MSG_KEXINIT
		byte[16]	cookie
		string		keyex algorithms
		string		pubkey algorithms
		string		client_crypto algorithms
		string		server_crypto algorithms
		string		client_mac algorithms
		string		server_mac algorithms
		string		client_compression algorithms
		string		server_compression algorithms
		string		client_language
		string		server_language
		boolean		first_keyex_packet_follows
		uint32		reserved

	   The cookie isn't explicitly processed as with SSHv1 since SSHv2
	   hashes the entire server hello message */
	length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_KEXINIT );
	if( cryptStatusError( length ) )
		return( length );
	if( length < ID_SIZE + SSH2_COOKIE_SIZE + \
				 ( ( LENGTH_SIZE + SSH2_MIN_ALGOID_SIZE ) * 6 ) + \
				 ( LENGTH_SIZE * 4 ) + BOOLEAN_SIZE + UINT_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid hello packet length %d", length );
	*keyexLength = length;
	bufPtr = sessionInfoPtr->receiveBuffer + ID_SIZE + SSH2_COOKIE_SIZE;
	length -= ID_SIZE + SSH2_COOKIE_SIZE;
	if( isServer )
		{
		/* DES is a placeholder for EDH (as opposed to the standard static
		   DH) */
		setAlgoIDInfo( &algoIDInfo, algoStringKeyexTbl, CRYPT_ALGO_DES, 
					   GETALGO_FIRST_MATCH_WARN );
		}
	else
		{
		setAlgoIDInfo( &algoIDInfo, algoStringKeyexTbl, CRYPT_ALGO_NONE, 
					   GETALGO_BEST_MATCH );
		}
	status = getAlgoIDEx( &algoIDInfo, bufPtr, length, sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( algoIDInfo.prefAlgoMismatch )
		/* We didn't get a match for our first choice, remember that we have
		   to discard any guessed keyex that may follow */
		preferredAlgoMismatch = TRUE;
	if( algoIDInfo.algo == CRYPT_ALGO_DES )
		/* If the keyex algorithm is the DES placeholder, we're using 
		   ephemeral rather than static DH keys and need to negotiate the 
		   keyex key before we can perform the exchange */
		handshakeInfo->requestedServerKeySize = SSH2_DEFAULT_KEYSIZE;
	bufPtr += algoIDInfo.algoStringLength;
	length -= algoIDInfo.algoStringLength;
	if( isServer )
		{
		setAlgoIDInfo( &algoIDInfo, handshakeInfo->algoStringPubkeyTbl, 
					   handshakeInfo->pubkeyAlgo, GETALGO_FIRST_MATCH_WARN );
		}
	else
		{
		setAlgoIDInfo( &algoIDInfo, handshakeInfo->algoStringPubkeyTbl, 
					   CRYPT_ALGO_NONE, GETALGO_BEST_MATCH );
		}
	status = getAlgoIDEx( &algoIDInfo, bufPtr, length, sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( !isServer )
		handshakeInfo->pubkeyAlgo = algoIDInfo.algo;
	if( algoIDInfo.prefAlgoMismatch )
		/* We didn't get a match for our first choice, remember that we have
		   to discard any guessed keyex that may follow */
		preferredAlgoMismatch = TRUE;
	bufPtr += algoIDInfo.algoStringLength;
	length -= algoIDInfo.algoStringLength;
	stringLength = getAlgoIDpair( ( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
									algoStringEncrTblServer : \
									algoStringEncrTblClient, 
								  &sessionInfoPtr->cryptAlgo, bufPtr, 
								  length, isServer, sessionInfoPtr );
	if( cryptStatusError( stringLength ) )
		return( stringLength );
	bufPtr += stringLength;
	length -= stringLength;
	stringLength = getAlgoIDpair( algoStringMACTbl,
								  &sessionInfoPtr->integrityAlgo, bufPtr, 
								  length, isServer, sessionInfoPtr );
	if( cryptStatusError( stringLength ) )
		return( stringLength );
	bufPtr += stringLength;
	length -= stringLength;
	stringLength = getAlgoIDpair( algoStringCoprTbl, NULL, bufPtr, 
								  length, isServer, sessionInfoPtr );
	if( cryptStatusError( stringLength ) )
		return( stringLength );
	bufPtr += stringLength;
	length -= stringLength;
	stringLength = mgetLong( bufPtr );
	if( stringLength < 0 || stringLength > length + LENGTH_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid hello packet client language string length %d", 
				stringLength );
	bufPtr += stringLength;
	length -= stringLength + LENGTH_SIZE;
	stringLength = mgetLong( bufPtr );
	if( stringLength < 0 || stringLength > length + LENGTH_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid hello packet server language string length %d", 
				stringLength );
	bufPtr += stringLength;
	length -= stringLength + LENGTH_SIZE;
	if( length != BOOLEAN_SIZE + UINT_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid hello packet length remainder size %d, expected "
				"%d", length, BOOLEAN_SIZE + UINT_SIZE );
	if( *bufPtr && preferredAlgoMismatch )
		/* There's a guessed keyex following this packet and we didn't match
		   the first-choice keyex/pubkey algorithm, tell the caller to skip 
		   it */
		return( OK_SPECIAL );
	return( CRYPT_OK );
	}

/* Process a global or channel request.  At the moment it's set up in allow-
   all mode, it may be necessary to switch to deny-all instead if clients 
   pop up that submit things that cause problems */

static int sendRequestResponse( SESSION_INFO *sessionInfoPtr,
								const BOOLEAN isChannelRequest,
								const BOOLEAN isSuccessful )
	{
	BYTE *bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;

	/* Indicate that the request succeeded/was denied:

		byte	type = SSH2_MSG_CHANNEL/GLOBAL_SUCCESS/FAILURE
	  [	uint32	channel_no		- For channel reqs ] */
	if( isChannelRequest )
		{
		*bufPtr++ = isSuccessful ? SSH2_MSG_CHANNEL_SUCCESS : \
								   SSH2_MSG_CHANNEL_FAILURE;
		mputLong( bufPtr, sessionInfoPtr->sshChannel );
		return( sendPacketSSH2( sessionInfoPtr, ID_SIZE + UINT_SIZE,
								FALSE ) );
		}
	*bufPtr++ = isSuccessful ? SSH2_MSG_GLOBAL_SUCCESS : \
							   SSH2_MSG_GLOBAL_FAILURE;
	return( sendPacketSSH2( sessionInfoPtr, ID_SIZE, FALSE ) );
	}

int processRequest( SESSION_INFO *sessionInfoPtr, const BYTE *data,
					const int dataLength )
	{
	static const FAR_BSS char *invalidRequests[] = \
			{ "x11-req", NULL };
	static const FAR_BSS char *validRequests[] = \
			{ "shell", "exec", "subsystem", NULL };
#if 0	/* Anything not matched defaults to being treated as a no-op */
	static const FAR_BSS char *noopRequests[] = \
			{ "pty-req", "env", "window-change", "xon-xoff", NULL };
#endif /* 0 */
	const BOOLEAN isChannelRequest = \
			( sessionInfoPtr->sshPacketType == SSH2_MSG_CHANNEL_REQUEST );
	BOOLEAN wantReply = FALSE;
	const char *requestNamePtr;
	int length = dataLength, stringLength, i;
	int extraLength = isChannelRequest ? UINT_SIZE : 0;

	/* Process the channel/global request:

		byte	type = SSH2_MSG_CHANNEL_REQUEST
	  [	uint32	recipient_channel	- For channel reqs ]
		string	request_type
		boolean	want_reply
		[...] */
	if( length < extraLength + ( LENGTH_SIZE + 1 ) + BOOLEAN_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid global/channel request packet length %d",
				length );
	if( isChannelRequest )
		{
		long channelNo;

		channelNo = mgetLong( data );
		if( channelNo != sessionInfoPtr->sshChannel )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid channel number %d, expected %d",
					channelNo, sessionInfoPtr->sshChannel );
		}
	stringLength = mgetLong( data );
	if( stringLength <= 0 || stringLength > CRYPT_MAX_TEXTSIZE || \
		length < extraLength + ( LENGTH_SIZE + stringLength ) + \
				 BOOLEAN_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid global/channel request packet length %d, "
				"string length %d", length, stringLength );
	length -= extraLength + ( LENGTH_SIZE + stringLength ) + BOOLEAN_SIZE;
	if( data[ stringLength ] )
		wantReply = TRUE;
	requestNamePtr = data;
	data += stringLength + BOOLEAN_SIZE;

	/* Check for requests that we don't allow */
	for( i = 0; invalidRequests[ i ] != NULL; i++ )
		if( stringLength == strlen( invalidRequests[ i ] ) && \
			!memcmp( requestNamePtr, invalidRequests[ i ], stringLength ) )
			return( sendRequestResponse( sessionInfoPtr, 
										 isChannelRequest, FALSE ) );

	/* If we're being asked for a subsystem, record the type */
	if( stringLength == 9 && !memcmp( requestNamePtr, "subsystem", 9 ) )
		{
		const int subsystemLength = mgetLong( data );

		/*	[...]
			string	subsystem_name */
		if( length != ( LENGTH_SIZE + subsystemLength ) || \
			subsystemLength <= 0 || subsystemLength > CRYPT_MAX_TEXTSIZE )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid channel request payload length %d, "
					"subsystem length %d", length, subsystemLength );
		memcpy( sessionInfoPtr->sshSubsystem, data, subsystemLength );
		sessionInfoPtr->sshSubsystemLength = subsystemLength;
		}

	/* If we're being asked for port forwarding, get the address and port 
	   information */
	if( stringLength == 13 && !memcmp( requestNamePtr, "tcpip-forward", 13 ) )
		{
		int status;

		/*	[...]
			string	address_to_bind (e.g. "0.0.0.0")
			uint32	port_to_bind */
		status = getAddressAndPort( sessionInfoPtr, data, length );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* We've got either a valid request or a no-op which is ignored, 
	   acknowledge it if necessary */
	if( wantReply )
		{
		int status;

		status = sendRequestResponse( sessionInfoPtr, isChannelRequest, 
									  TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's a valid request, we're done and can exit.  Anything else is a 
	  no-op */
	for( i = 0; validRequests[ i ] != NULL; i++ )
		if( stringLength == strlen( validRequests[ i ] ) && \
			!memcmp( requestNamePtr, validRequests[ i ], stringLength ) )
			return( OK_SPECIAL );

	return( CRYPT_OK );
	}

/* Complete the DH key agreement */

int completeKeyex( SESSION_INFO *sessionInfoPtr, 
				   SSH_HANDSHAKE_INFO *handshakeInfo, 
				   const BOOLEAN isServer )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	RESOURCE_DATA msgData;
	int status;

	/* Read the other side's key agreement information */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	status = keyAgreeParams.publicValueLen = \
				readKeyexMPI( sessionInfoPtr,
							  keyAgreeParams.publicValue, 
							  isServer ? handshakeInfo->clientKeyexValue : \
										 handshakeInfo->serverKeyexValue,
							  handshakeInfo->serverKeySize );
	if( cryptStatusError( status ) )
		return( status );

	/* Perform phase 2 of the DH key agreement */
	status = krnlSendMessage( handshakeInfo->iServerCryptContext,
							  IMESSAGE_CTX_DECRYPT, &keyAgreeParams,
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusOK( status ) )
		{
		memcpy( handshakeInfo->secretValue, keyAgreeParams.wrappedKey,
				keyAgreeParams.wrappedKeyLen );
		handshakeInfo->secretValueLength = keyAgreeParams.wrappedKeyLen;
		}
	zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using ephemeral DH, hash the requested keyex key length(s) 
	   and DH p and g values.  Since this has been deferred until long after 
	   the keyex negotiation took place, we have to recreate the original 
	   encoded values here */
	if( handshakeInfo->requestedServerKeySize > 0 )
		{
		BYTE keyexBuffer[ 128 + ( CRYPT_MAX_PKCSIZE * 2 ) ];
		const int extraLength = LENGTH_SIZE + ( LENGTH_SIZE + 6 );

		krnlSendMessage( handshakeInfo->iExchangeHashcontext,
						 IMESSAGE_CTX_HASH, 
						 handshakeInfo->encodedReqKeySizes, 
						 handshakeInfo->encodedReqKeySizesLength );
		setMessageData( &msgData, keyexBuffer, 
						128 + ( CRYPT_MAX_PKCSIZE * 2 ) );
		status = krnlSendMessage( handshakeInfo->iServerCryptContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_SSH2 );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendMessage( handshakeInfo->iExchangeHashcontext, 
						 IMESSAGE_CTX_HASH, keyexBuffer + extraLength, 
						 msgData.length - extraLength );
		}

	/* Hash the client and server DH values and shared secret */
	krnlSendMessage( handshakeInfo->iExchangeHashcontext, IMESSAGE_CTX_HASH, 
					 handshakeInfo->clientKeyexValue,
					 handshakeInfo->clientKeyexValueLength );
	krnlSendMessage( handshakeInfo->iExchangeHashcontext, IMESSAGE_CTX_HASH,
					 handshakeInfo->serverKeyexValue,
					 handshakeInfo->serverKeyexValueLength );
	status = hashAsMPI( handshakeInfo->iExchangeHashcontext,
						handshakeInfo->secretValue,
						handshakeInfo->secretValueLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Complete the hashing to obtain the exchange hash and then hash *that*
	   to get the hash that the server signs and sends to the client.  The
	   overall hashed data for the exchange hash is:

		string	V_C, client version string (CR and NL excluded)
		string	V_S, server version string (CR and NL excluded)
		string	I_C, client SSH_MSG_KEXINIT
		string	I_S, server SSH_MSG_KEXINIT
		string	K_S, the host key
	 [[	uint32	min, min.preferred keyex key size for ephemeral DH ]]
	  [	uint32	n, preferred keyex key size for ephemeral DH ]
	 [[	uint32	max, max.preferred keyex key size for ephemeral DH ]]
	  [	mpint	p, DH p for ephemeral DH ]
	  [	mpint	g, DH g for ephemeral DH ]
		mpint	e, client DH keyex value
		mpint	f, server DH keyex value
		mpint	K, the shared secret */
	krnlSendMessage( handshakeInfo->iExchangeHashcontext, IMESSAGE_CTX_HASH,
					 "", 0 );
	setMessageData( &msgData, handshakeInfo->sessionID, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( handshakeInfo->iExchangeHashcontext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	handshakeInfo->sessionIDlength = msgData.length;
	krnlSendMessage( handshakeInfo->iExchangeHashcontext,
					 IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( handshakeInfo->iExchangeHashcontext,
					 IMESSAGE_CTX_HASH, handshakeInfo->sessionID,
					 handshakeInfo->sessionIDlength );
	return( krnlSendMessage( handshakeInfo->iExchangeHashcontext,
							 IMESSAGE_CTX_HASH, "", 0 ) );
	}

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Read data over the SSHv2 link */

static int readHeaderFunction( SESSION_INFO *sessionInfoPtr,
							   READSTATE_INFO *readInfo )
	{
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufPos;
	long length;
	int extraLength = 0, status;

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* Make sure that there's room left to handle the speculative read */
	if( sessionInfoPtr->receiveBufPos >= \
		sessionInfoPtr->receiveBufSize - 128 )
		return( 0 );

	/* Try and read the header data from the remote system */
	assert( sessionInfoPtr->receiveBufPos == sessionInfoPtr->receiveBufEnd );
	status = readFixedHeader( sessionInfoPtr, MIN_PACKET_SIZE );
	if( status <= 0 )
		return( status );

	/* Process the header data.  Since data errors are always fatal, we make
	   all errors fatal until we've finished handling the header */
	*readInfo = READINFO_FATAL;
	assert( status == MIN_PACKET_SIZE );
	status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_CTX_DECRYPT, bufPtr, MIN_PACKET_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	length = mgetLong( bufPtr );
	if( length < MIN_PACKET_SIZE - LENGTH_SIZE || \
		length > sessionInfoPtr->receiveBufSize - \
				 ( sessionInfoPtr->authBlocksize + MIN_PACKET_SIZE + 8 ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid decrypted packet length %d", length );
	macPayload( sessionInfoPtr->iAuthInContext, sessionInfoPtr->readSeqNo,
				bufPtr, MIN_PACKET_SIZE - LENGTH_SIZE, length, MAC_START );

	/* Extract fixed information, adjust the overall length for the fixed
	   information we've removed and the (implicitly present) MAC data, and
	   move the remainder down to the start of the buffer.  The general idea
	   is to remove all of the header data so that only the payload remains 
	   in the buffer, avoiding the need to move it down afterwards.  This is
	   complicated by the fact that (unlike SSL) all of the data (including
	   the header) is encrypted and MAC'ed, so we can't just read that
	   separately but have to process it as part of the payload, remove it,
	   and remember anything that's left for later.  The general header data
	   is:

		byte		padLen
		byte		packetType
		uint32		channel_no
		uint32		length

	   of which the last two fields are only present for payload packets */
	sessionInfoPtr->sshPadLength = *bufPtr++;
	sessionInfoPtr->sshPacketType = *bufPtr++;
	length += sessionInfoPtr->authBlocksize - ( ID_SIZE + PADLENGTH_SIZE );
	if( sessionInfoPtr->sshPacketType == SSH2_MSG_CHANNEL_DATA )
		{
		long channelNo, payloadLength;

		/* If it's channel data, strip the encapsulation, which allows us to
		   process the payload directly without having to move it around in
		   the buffer */
		channelNo = mgetLong( bufPtr );
		if( channelNo != sessionInfoPtr->sshChannel )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid channel number %d, expected %d",
					channelNo, sessionInfoPtr->sshChannel );
		payloadLength = mgetLong( bufPtr );
		if( length - payloadLength != UINT_SIZE + LENGTH_SIZE + \
									  sessionInfoPtr->sshPadLength + \
									  sessionInfoPtr->authBlocksize )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid packet payload length %d, total length %d",
					payloadLength, length );
		extraLength = UINT_SIZE + LENGTH_SIZE;
		}
	memmove( sessionInfoPtr->receiveBuffer + sessionInfoPtr->receiveBufPos,
			 bufPtr, SSH2_PACKET_REMAINDER_SIZE - extraLength );

	/* Determine how much data we'll be expecting */
	sessionInfoPtr->pendingPacketLength = \
			sessionInfoPtr->pendingPacketRemaining = length - extraLength;

	/* Indicate that we got some payload as part of the header */
	*readInfo = READINFO_HEADERPAYLOAD;
	return( SSH2_PACKET_REMAINDER_SIZE - extraLength );
	}

static int processBodyFunction( SESSION_INFO *sessionInfoPtr,
								READSTATE_INFO *readInfo )
	{
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufPos;
	long length = ( sessionInfoPtr->pendingPacketLength - \
					sessionInfoPtr->pendingPacketPartialLength ) - \
				  sessionInfoPtr->authBlocksize;
	int status;

	/* All errors processing the payload are fatal */
	*readInfo = READINFO_FATAL;

	/* Decrypt the packet in the buffer and MAC the payload */
	status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
						IMESSAGE_CTX_DECRYPT,
						bufPtr + sessionInfoPtr->pendingPacketPartialLength,
						length );
	if( cryptStatusError( status ) )
		return( status );
	if( !macPayload( sessionInfoPtr->iAuthInContext, 0,
					 bufPtr + sessionInfoPtr->pendingPacketPartialLength,
					 length, 0, MAC_END ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE, "Bad message MAC" );

	/* Strip the padding and MAC and update the state information */
	length = sessionInfoPtr->pendingPacketLength - \
			 ( sessionInfoPtr->sshPadLength + sessionInfoPtr->authBlocksize );
	sessionInfoPtr->readSeqNo++;

	/* See what we got.  SSHv2 has a pile of no-op-equivalents that we have
	   to handle as well as the obvious no-ops.  We can also get global and
	   channel requests for assorted reasons (none of which we care about) and
	   a constant stream of window adjust messages to implement the SSH
	   performance handbrake */
	if( sessionInfoPtr->sshPacketType == SSH2_MSG_GLOBAL_REQUEST || \
		sessionInfoPtr->sshPacketType == SSH2_MSG_CHANNEL_REQUEST )
		{
		status = processRequest( sessionInfoPtr, bufPtr, length );
		if( cryptStatusError( status ) )
			return( status );

		/* Turn the packet into a no-op */
		sessionInfoPtr->sshPacketType = SSH2_MSG_IGNORE;
		}
	if( sessionInfoPtr->sshPacketType == SSH2_MSG_CHANNEL_OPEN )
		{
		/* If it's a channel open this could be a port-forwarding request */
		status = processChannelOpen( sessionInfoPtr, bufPtr, length );
		if( cryptStatusError( status ) )
			return( status );

		/* Turn the packet into a no-op */
		sessionInfoPtr->sshPacketType = SSH2_MSG_IGNORE;
		}
	if( sessionInfoPtr->sshPacketType == SSH2_MSG_IGNORE || \
		sessionInfoPtr->sshPacketType == SSH2_MSG_DEBUG || \
		sessionInfoPtr->sshPacketType == SSH2_MSG_CHANNEL_WINDOW_ADJUST )
		{
		/* Nothing to see here, move along, move along */
		sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos;
		sessionInfoPtr->pendingPacketLength = 0;
		*readInfo = READINFO_NOOP;
		return( OK_SPECIAL );	/* Tell the caller to try again */
		}
	if( sessionInfoPtr->sshPacketType == SSH2_MSG_CHANNEL_EOF || \
		sessionInfoPtr->sshPacketType == SSH2_MSG_CHANNEL_CLOSE )
		{
		/* The peer has closed its write side of the channel, mark it as
		   closed for reading purposes.  Note that our write channel remains
		   open until the caller closes it by closing the session.

		   According to the SSH docs the EOF packet is mostly a courtesy 
		   notification (actually the docs are somewhat muddled about the
		   semantics of EOF vs.close, see the longer comments in the shutdown
		   function), however many implementations seem to use a channel EOF 
		   in place of a close so rather than turning it into a no-op by
		   translating it into an SSH2_MSG_IGNORE we instead treat it as an
		   SSH2_MSG_CHANNEL_CLOSE */
		sessionInfoPtr->flags |= SESSION_SENDCLOSED;
		sessionInfoPtr->protocolFlags |= SSH_PFLAG_CHANNELCLOSED;
		retExt( sessionInfoPtr, CRYPT_ERROR_COMPLETE,
				( sessionInfoPtr->sshPacketType == SSH2_MSG_CHANNEL_CLOSE ) ? \
				"Remote system closed SSH channel" : \
				"Remote system closed SSH channel by sending channel EOF" );
		}
	if( sessionInfoPtr->sshPacketType == SSH2_MSG_DISCONNECT )
		return( getDisconnectInfo( sessionInfoPtr,
							sessionInfoPtr->receiveBuffer + ID_SIZE ) );
	if( sessionInfoPtr->sshPacketType == SSH2_MSG_KEXINIT )
		{
		/* The SSH spec is extremely vague about the sequencing of operations
		   during a rehandshake.  Unlike SSL, there is no real indication of
		   what happens to the connection-layer transfers while a transport-
		   layer rehandshake is in progress.  Also unlike SSL, we can't
		   refuse a rehandshake by ignoring the request, so once we've fallen
		   we can't get up any more.  This is most obvious with ssh.com's
		   server, which by default will do a rehandshake every hour (for a
		   basic encrypted telnet session, while a high-volume IPsec link can
		   run for hours before it feels the need to do this).  To make
		   things even messier, neither side can block for too long waiting
		   for the rehandshake to complete before sending new data because
		   the lack of WINDOW_ADJUSTs (in an implementation that sends
		   these with almost every packet, as most do) will screw up flow
		   control and lead to deadlock.

		   To avoid falling into this hole, or at least to fail obviously
		   when the two sides can't agree on how to handle the layering
		   mismatch problem, we report a rehandshake request as an error.
		   Trying to handle it results in hard-to-diagnose (it depends on
		   what the layers are doing at the time of the problem) errors,
		   typically some bad-packet error when the other side tries to
		   interpret a connection-layer packet as part of the rehandshake,
		   or when the two sides disagree on when to switch keys and it
		   decrypts with the wrong keys and gets a garbled packet type */
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Unexpected KEXINIT request received" );
		}

	/* Adjust the data window and comunicate changes to the other side if
	   necessary.  See the comment in the client-side handshake code for
	   the reason for the window size handling */
	sessionInfoPtr->sshWindowCount += length;
	if( ( sessionInfoPtr->sshWindowCount > \
						MAX_WINDOW_SIZE - sessionInfoPtr->sendBufSize ) || \
		( sessionInfoPtr->protocolFlags & SSH_PFLAG_WINDOWBUG ) )
		{
		/* Send the window adjust to the remote system.  We ignore any
		   possible error code from the packet send because we're supposed
		   to be processing a read and not a write at this point, the write
		   is only required by SSH's silly flow-control handling */
		bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
		*bufPtr++ = SSH2_MSG_CHANNEL_WINDOW_ADJUST;
		mputLong( bufPtr, sessionInfoPtr->sshChannel );
		mputLong( bufPtr, MAX_WINDOW_SIZE );
		sendPacketSSH2( sessionInfoPtr, ID_SIZE + UINT_SIZE + UINT_SIZE,
						FALSE );

		/* We've reset the window, start again from zero */
		sessionInfoPtr->sshWindowCount = 0;
		}

	/* Handle any further packets that consume window space.  The difference 
	   between no-op'ing the packet out at this point and doing it earlier is
	   that this data consumes window space, so we have to handle it after
	   we've done any window adjustment */
	if( sessionInfoPtr->sshPacketType == SSH2_MSG_CHANNEL_EXTENDED_DATA )
		{
		/* Nothing to see here, move along, move along */
		sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos;
		sessionInfoPtr->pendingPacketLength = 0;
		*readInfo = READINFO_NOOP;
		return( OK_SPECIAL );	/* Tell the caller to try again */
		}

	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos + length;
	sessionInfoPtr->receiveBufPos = sessionInfoPtr->receiveBufEnd;
	sessionInfoPtr->pendingPacketLength = 0;

	*readInfo = READINFO_NONE;
	return( length );
	}

/* Write data over the SSHv2 link */

static int writeDataFunction( SESSION_INFO *sessionInfoPtr )
	{
	BYTE *bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	const int dataLength = sessionInfoPtr->sendBufPos - \
						   ( SSH2_HEADER_SIZE + SSH2_PAYLOAD_HEADER_SIZE );
	int status;

	assert( !( sessionInfoPtr->flags & SESSION_SENDCLOSED ) );
	assert( !( sessionInfoPtr->protocolFlags & SSH_PFLAG_CHANNELCLOSED ) );

	/* Send the data through to the remote system:

		byte		SSH2_MSG_CHANNEL_DATA
		uint32		channel_no
		string		data */
	*bufPtr++ = SSH2_MSG_CHANNEL_DATA;
	mputLong( bufPtr, sessionInfoPtr->sshChannel );
	mputLong( bufPtr, dataLength );
	status = sendPacketSSH2( sessionInfoPtr,
							 SSH2_PAYLOAD_HEADER_SIZE + dataLength, 
							 FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* We've flushed everything through, go back to the start of the
	   buffer */
	sessionInfoPtr->sendBufPos = SSH2_HEADER_SIZE + \
								 SSH2_PAYLOAD_HEADER_SIZE;
	return( CRYPT_OK );
	}

/* Close a previously-opened SSH session */

static void shutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	BYTE *bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	READSTATE_INFO readInfo;
	int savedTimeout, status;

	/* If we haven't entered the secure state yet (i.e. we're still in the
	   middle of the handshake), this is an abnormal termination, send a
	   disconnect indication:

		byte		SSH_MSG_DISCONNECT
		uint32		reason code = SSH_DISCONNECT_PROTOCOL_ERROR
		string		description [RFC2279]
		string		language tag [RFC1766] */
	if( !( sessionInfoPtr->flags & SESSION_ISSECURE ) )
		{
		const int length = ID_SIZE + UINT_SIZE + \
						   encodeString( NULL, "Handshake failed", 16 ) + \
						   encodeString( NULL, "", 0 );

		*bufPtr++ = SSH2_MSG_DISCONNECT;
		mputLong( bufPtr, 2 );	/* SSH_DISCONNECT_PROTOCOL_ERROR */
		bufPtr += encodeString( bufPtr, "Handshake failed", 16 );
		encodeString( bufPtr, "", 0 );
		sendPacketSSH2( sessionInfoPtr, length, FALSE );
		sNetDisconnect( &sessionInfoPtr->stream );
		return;
		}

	/* Close the channel:

		byte		SSH2_MSG_CHANNEL_CLOSE
		uint32		channel_no */
	*bufPtr++ = SSH2_MSG_CHANNEL_CLOSE;
	mputLong( bufPtr, sessionInfoPtr->sshChannel );
	status = sendPacketSSH2( sessionInfoPtr, ID_SIZE + UINT_SIZE, FALSE );
	if( cryptStatusError( status ) || \
		( sessionInfoPtr->protocolFlags & SSH_PFLAG_CHANNELCLOSED ) )
		{
		/* There's a problem at the network level or the other side has
		   already closed the channel, close the network link and exit */
		sNetDisconnect( &sessionInfoPtr->stream );
		return;
		}
	if( sessionInfoPtr->receiveBufSize - sessionInfoPtr->receiveBufEnd < \
		min( sessionInfoPtr->pendingPacketRemaining, 1024 ) )
		{
		/* If there's not enough room in the receive buffer to read at least
		   1K of packet data, we can't try anything further */
		sNetDisconnect( &sessionInfoPtr->stream );
		return;
		}

	/* Read back the other side's channel close.  This is somewhat messy
	   since the other side could decide that it still wants to send us
	   arbitrary amounts of data (the spec is rather vague about how urgent
	   a channel close is, the general idea among implementors seems to be
	   that you should let output drain before you close your side, but
	   if you're in the middle of sending a 2GB file that's a lot of output
	   to drain).  Since we're about to shut down the session anyway, we try
	   to read a basic channel close ack from the other side, if there's
	   anything more than that we drop it.

	   This is complicated somewhat by the fact that what we're doing here is
	   something that's normally handled by the high-level read code in
	   cryptses.c.  What we implement here is the absolute minimum needed to
	   clear the stream: Set a (small) nonzero timeout if required, read the
	   data, and discard it */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_TIMEOUT, &savedTimeout, 0 );
	if( savedTimeout < 2 || savedTimeout > 15 )
		/* Set a timeout sufficient to at least provide a chance of getting 
		   the data, but without leading to excessive delays during the
		   shutdown */
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_TIMEOUT, NULL, 2 );
	status = sessionInfoPtr->readHeaderFunction( sessionInfoPtr, &readInfo );
	if( !cryptStatusError( status ) )
		{
		/* Adjust the packet info for the packet header data that was just
		   read */
		sessionInfoPtr->receiveBufEnd += status;
		sessionInfoPtr->pendingPacketPartialLength = status;
		sessionInfoPtr->pendingPacketRemaining -= status;
		if( sessionInfoPtr->pendingPacketRemaining <= 512 )
			{
			const int bytesLeft = sessionInfoPtr->receiveBufSize - \
								  sessionInfoPtr->receiveBufEnd;

			/* We got a packet and it's probably the channel close ack, read
			   it */
			status = sread( &sessionInfoPtr->stream,
							sessionInfoPtr->receiveBuffer + \
								sessionInfoPtr->receiveBufEnd,
							min( sessionInfoPtr->pendingPacketRemaining, \
								 bytesLeft ) );
			}
		}
	sNetDisconnect( &sessionInfoPtr->stream );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

void initSSH2processing( SESSION_INFO *sessionInfoPtr,
						 SSH_HANDSHAKE_INFO *handshakeInfo,
						 const BOOLEAN isServer )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		FALSE,						/* Request-response protocol */
		SESSION_NONE,				/* Flags */
		SSH_PORT,					/* SSH port */
		SESSION_NEEDS_USERID |		/* Client attributes */
			SESSION_NEEDS_PASSWORD | \
			SESSION_NEEDS_KEYORPASSWORD | \
			SESSION_NEEDS_PRIVKEYSIGN,
				/* The client private key is optional but if present, it has 
				   to be signature-capable */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYSIGN,
		2, 1, 2,					/* Version 2 */
		NULL, NULL,					/* Content-type */

		/* Protocol-specific information */
		EXTRA_PACKET_SIZE + \
			DEFAULT_PACKET_SIZE,	/* Send/receive buffer size */
		SSH2_HEADER_SIZE + \
			SSH2_PAYLOAD_HEADER_SIZE,/* Payload data start */
		EXTRA_PACKET_SIZE + \
			DEFAULT_PACKET_SIZE		/* Payload data end */
		};

	sessionInfoPtr->protocolInfo = &protocolInfo;
	sessionInfoPtr->readHeaderFunction = readHeaderFunction;
	sessionInfoPtr->processBodyFunction = processBodyFunction;
	sessionInfoPtr->writeDataFunction = writeDataFunction;
	if( handshakeInfo != NULL )
		{
		if( isServer )
			initSSH2serverProcessing( sessionInfoPtr, handshakeInfo );
		else
			initSSH2clientProcessing( sessionInfoPtr, handshakeInfo );

		handshakeInfo->algoStringPubkeyTbl = algoStringPubkeyTbl;
		handshakeInfo->algoStringUserauthentTbl = algoStringUserauthentTbl;
		}

	/* SSHv2 has slightly different data handling than SSHv1, if we're
	   targeted at SSHv1 we need to override the default shutdown function
	   with one that sends the appropriate close notification before closing
	   the network connection */
	sessionInfoPtr->shutdownFunction = shutdownFunction;
	}
#endif /* USE_SSH2 */
