/****************************************************************************
*																			*
*					ASN.1 Supplemental Read/Write Routines					*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "asn1_rw.h"
  #include "asn1s_rw.h"
#else
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Object Identifier Routines						*
*																			*
****************************************************************************/

/* A table mapping OID's to algorithm types.  We take advantage of the fact
   that object identifiers were designed to be handled in the encoded form
   (without any need for decoding) and compare expected OID's with the raw
   encoded form.  Some OID's are for pure algorithms, others are for aWithB
   type combinations (usually encryption + hash), in this case the algorithm
   is the encryption and the subAlgorithm is the hash.

   There are multiple OID's for RSA, the main ones being rsa (which doesn't
   specify an exact data format and is deprecated), rsaEncryption (as per
   PKCS #1, recommended), and rsaSignature (ISO 9796).  We use rsaEncryption
   and its derived forms (e.g. md5WithRSAEncryption) rather than alternatives
   like md5WithRSA.  There is also an OID for rsaKeyTransport that uses
   PKCS #1 padding but isn't defined by RSADSI.

   There are a great many OIDs for DSA and/or SHA.  We list the less common 
   ones after all the other OIDs so that we always encode the more common 
   form, but can decode many forms (there are even more OIDs for SHA or DSA 
   with common parameters that we don't bother with).
   
   AES has a whole series of OIDs that vary depending on the key size used, 
   this isn't of any use since we can tell the keysize from other places so 
   we just treat them all as a generic single AES OID */

static const FAR_BSS struct {
	const CRYPT_ALGO_TYPE algorithm;	/* The basic algorithm */
	const CRYPT_ALGO_TYPE subAlgorithm;	/* The algorithm subtype */
	const BYTE *oid;					/* The OID for this algorithm */
	} algoIDmap[] = {
	/* RSA and <hash>WithRSA */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" ) },
	  /* rsaEncryption (1 2 840 113549 1 1 1) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_MD2,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x02" ) },
	  /* md2withRSAEncryption (1 2 840 113549 1 1 2) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_MD4,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x03" ) },
	  /* md4withRSAEncryption (1 2 840 113549 1 1 3) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_MD5,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04" ) },
	  /* md5withRSAEncryption (1 2 840 113549 1 1 4) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05" ) },
	  /* sha1withRSAEncryption (1 2 840 113549 1 1 5) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x06\x2B\x24\x03\x03\x01\x01" ) },
	  /* Another rsaSignatureWithsha1 (1 3 36 3 3 1 1) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_RIPEMD160,
	  MKOID( "\x06\x06\x2B\x24\x03\x03\x01\x02" ) },
	  /* rsaSignatureWithripemd160 (1 3 36 3 3 1 2) */

	/* DSA and dsaWith<hash> */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x04\x01" ) },
	  /* dsa (1 2 840 10040 4 1) */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x0C" ) },
	  /* Peculiar deprecated dsa (1 3 14 3 2 12), but used by CDSA and the
	     German PKI profile */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x04\x03" ) },
	  /* dsaWithSha1 (1 2 840 10040 4 3) */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x1B" ) },
	  /* Another dsaWithSHA1 (1 3 14 3 2 27) */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x02" ) },
	  /* Yet another dsaWithSHA-1 (2 16 840 1 101 2 1 1 2) */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x0D" ) },
	  /* When they ran out of valid dsaWithSHA's, they started using invalid
	     ones.  This one is from JDK 1.1 and is actually dsaWithSHA, but it's
		 used as if it were dsaWithSHA-1 (1 3 14 3 2 13) */

	/* Elgamal and elgamalWith<hash> */
	{ CRYPT_ALGO_ELGAMAL, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x02\x01" ) },
	  /* elgamal (1 3 6 1 4 1 3029 1 2 1) */
	{ CRYPT_ALGO_ELGAMAL, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x97\x55\x01\x02\x01\x01" ) },
	  /* elgamalWithSHA-1 (1 3 6 1 4 1 3029 1 2 1 1) */
	{ CRYPT_ALGO_ELGAMAL, CRYPT_ALGO_RIPEMD160,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x97\x55\x01\x02\x01\x02" ) },
	  /* elgamalWithRIPEMD-160 (1 3 6 1 4 1 3029 1 2 1 2) */

	/* DH */
	{ CRYPT_ALGO_DH, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x07\x2A\x86\x48\xCE\x3E\x02\x01" ) },
	  /* dhPublicKey (1 2 840 10046 2 1) */

	/* KEA */
	{ CRYPT_ALGO_KEA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x16" ) },
	  /* keyExchangeAlgorithm (2 16 840 1 101 2 1 1 22) */

	/* Hash algorithms */
	{ CRYPT_ALGO_MD2, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x02" ) },
	  /* md2 (1 2 840 113549 2 2) */
	{ CRYPT_ALGO_MD2, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x0B\x60\x86\x48\x01\x86\xF8\x37\x01\x02\x08\x28" ) },
	  /* Another md2 (2 16 840 1 113719 1 2 8 40) */
	{ CRYPT_ALGO_MD4, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x04" ) },
	  /* md4 (1 2 840 113549 2 4) */
	{ CRYPT_ALGO_MD4, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x02\x82\x06\x01\x0A\x01\x03\x01" ) },
	  /* Another md4 (0 2 262 1 10 1 3 1) */
	{ CRYPT_ALGO_MD4, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x0B\x60\x86\x48\x01\x86\xF8\x37\x01\x02\x08\x5F" ) },
	  /* Yet another md4 (2 16 840 1 113719 1 2 8 95) */
	{ CRYPT_ALGO_MD5, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x05" ) },
	  /* md5 (1 2 840 113549 2 5) */
	{ CRYPT_ALGO_MD5, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x02\x82\x06\x01\x0A\x01\x03\x02" ) },
	  /* Another md5 (0 2 262 1 10 1 3 2) */
	{ CRYPT_ALGO_MD5, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x0B\x60\x86\x48\x01\x86\xF8\x37\x01\x02\x08\x32" ) },
	  /* Yet another md5 (2 16 840 1 113719 1 2 8 50) */
	{ CRYPT_ALGO_SHA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x1A" ) },
	  /* sha1 (1 3 14 3 2 26) */
	{ CRYPT_ALGO_SHA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x0B\x60\x86\x48\x01\x86\xF8\x37\x01\x02\x08\x52" ) },
	  /* Another sha1 (2 16 840 1 113719 1 2 8 82) */
	{ CRYPT_ALGO_RIPEMD160, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x05\x2B\x24\x03\x02\x01" ) },
	  /* ripemd160 (1 3 36 3 2 1) */
	{ CRYPT_ALGO_RIPEMD160, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x02\x82\x06\x01\x0A\x01\x03\x08" ) },
	  /* Another ripemd160 (0 2 262 1 10 1 3 8) */
#ifdef USE_SHA2
	{ CRYPT_ALGO_SHA2, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01" ) },
	  /* SHA2-256 (2 16 840 1 101 3 4 2 1) */
	{ CRYPT_ALGO_SHA2, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02" ) },
	  /* SHA2-384 (2 16 840 1 101 3 4 2 2) */
	{ CRYPT_ALGO_SHA2, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03" ) },
	  /* SHA2-512 (2 16 840 1 101 3 4 2 3) */
#endif /* USE_SHA2 */

	/* MAC algorithms */
	{ CRYPT_ALGO_HMAC_MD5, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x08\x01\x01" ) },
	  /* hmac-MD5 (1 3 6 1 5 5 8 1 1) */
	{ CRYPT_ALGO_HMAC_SHA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x08\x01\x02" ) },
	  /* hmac-SHA (1 3 6 1 5 5 8 1 2) */
	{ CRYPT_ALGO_HMAC_SHA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x07" ) },
	  /* Another hmacWithSHA1 (1 2 840 113549 2 7) */

	/* Ciphers */
	{ CRYPT_ALGO_AES, CRYPT_MODE_ECB,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x01" ) },
	  /* aes128-ECB (2 16 840 1 101 3 4 1 1) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_ECB,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x15" ) },
	  /* aes192-ECB (2 16 840 1 101 3 4 1 21) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_ECB,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x29" ) },
	  /* aes256-ECB (2 16 840 1 101 3 4 1 41) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x02" ) },
	  /* aes128-CBC (2 16 840 1 101 3 4 1 2) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x16" ) },
	  /* aes192-CBC (2 16 840 1 101 3 4 1 22) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2A" ) },
	  /* aes256-CBC (2 16 840 1 101 3 4 1 42) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_OFB,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x03" ) },
	  /* aes128-OFB (2 16 840 1 101 3 4 1 3) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_OFB,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x17" ) },
	  /* aes192-OFB (2 16 840 1 101 3 4 1 23) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_OFB,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2B" ) },
	  /* aes256-OFB (2 16 840 1 101 3 4 1 43) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_CFB,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x04" ) },
	  /* aes128-CFB (2 16 840 1 101 3 4 1 4) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_CFB,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x18" ) },
	  /* aes192-CFB (2 16 840 1 101 3 4 1 24) */
	{ CRYPT_ALGO_AES, CRYPT_MODE_CFB,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2C" ) },
	  /* aes256-CFB (2 16 840 1 101 3 4 1 44) */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_ECB,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x01\x01" ) },
	  /* blowfishECB (1 3 6 1 4 1 3029 1 1 1) */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CBC,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x01\x02" ) },
	  /* blowfishCBC (1 3 6 1 4 1 3029 1 1 2) */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CFB,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x01\x03" ) },
	  /* blowfishCFB (1 3 6 1 4 1 3029 1 1 3) */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_OFB,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x01\x04" ) },
	  /* blowfishOFB (1 3 6 1 4 1 3029 1 1 4) */
	{ CRYPT_ALGO_CAST, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF6\x7D\x07\x42\x0A" ) },
	  /* cast5CBC (1 2 840 113533 7 66 10) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x06" ) },
	  /* desECB (1 3 14 3 2 6) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x02\x01" ) },
	  /* Another desECB (0 2 262 1 10 1 2 2 1) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x07" ) },
	  /* desCBC (1 3 14 3 2 7) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x02\x02" ) },
	  /* Another desCBC (0 2 262 1 10 1 2 2 2) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x08" ) },
	  /* desOFB (1 3 14 3 2 8) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x02\x03" ) },
	  /* Another desOFB (0 2 262 1 10 1 2 2 3) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x09" ) },
	  /* desCFB (1 3 14 3 2 9) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x02\x05" ) },
	  /* Another desCFB (0 2 262 1 10 1 2 2 5) */
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x07" ) },
	  /* des-EDE3-CBC (1 2 840 113549 3 7) */
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x03\x02" ) },
	  /* Another des3CBC (0 2 262 1 10 1 2 3 2) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x01" ) },
	  /* ideaECB (1 3 6 1 4 1 188 7 1 1 1) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB,
	  MKOID( "\x06\x06\x2B\x24\x03\x01\x02\x01" ) },
	  /* Another ideaECB (1 3 36 3 1 2 1) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x05\x01" ) },
	  /* Yet another ideaECB (0 2 262 1 10 1 2 5 1) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x02" ) },
	  /* ideaCBC (1 3 6 1 4 1 188 7 1 1 2) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC,
	  MKOID( "\x06\x06\x2B\x24\x03\x01\x02\x02" ) },
	  /* Another ideaCBC (1 3 36 3 1 2 2) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x05\x02" ) },
	  /* Yet another ideaCBC (0 2 262 1 10 1 2 5 2) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x04" ) },
	  /* ideaOFB (1 3 6 1 4 1 188 7 1 1 4) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB,
	  MKOID( "\x06\x06\x2B\x24\x03\x01\x02\x03" ) },
	  /* Another ideaOFB (1 3 36 3 1 2 3) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x05\x03" ) },
	  /* Yet another ideaOFB (0 2 262 1 10 1 2 5 3) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x03" ) },
	  /* ideaCFB (1 3 6 1 4 1 188 7 1 1 3) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB,
	  MKOID( "\x06\x06\x2B\x24\x03\x01\x02\x04" ) },
	  /* Another ideaCFB (1 3 36 3 1 2 4) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x05\x05" ) },
	  /* Yet another ideaCFB (0 2 262 1 10 1 2 5 5) */
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CBC,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x02" ) },
	  /* rc2CBC (1 2 840 113549 3 2) */
	{ CRYPT_ALGO_RC2, CRYPT_MODE_ECB,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x03" ) },
	  /* rc2ECB (1 2 840 113549 3 3) */
	{ CRYPT_ALGO_RC4, CRYPT_MODE_OFB,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x04" ) },
	  /* rc4 (1 2 840 113549 3 4) */
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CBC,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x09" ) },
	  /* rC5-CBCPad (1 2 840 113549 3 9) */
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CBC,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x08" ) },
	  /* rc5CBC (sometimes used interchangeably with the above) (1 2 840 113549 3 8) */
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x04" ) },
	  /* fortezzaConfidentialityAlgorithm (2 16 840 1 101 2 1 1 4) */

	{ CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, NULL }
	};

/* Map an OID to an algorithm type.  The subAlgorithm parameter can be
   NULL, in which case we don't return the sub-algorithm, but we return
   an error code if the OID has a sub-algorithm type */

static CRYPT_ALGO_TYPE oidToAlgorithm( const BYTE *oid, int *subAlgorithm )
	{
	const int oidSize = sizeofOID( oid );
	int i;

	for( i = 0; algoIDmap[ i ].algorithm != CRYPT_ALGO_NONE; i++ )
		if( sizeofOID( algoIDmap[ i ].oid ) == oidSize && \
			!memcmp( algoIDmap[ i ].oid, oid, oidSize ) )
			{
			if( subAlgorithm != NULL )
				/* Return the sub-algorithm type */
				*subAlgorithm = algoIDmap[ i ].subAlgorithm;
			else
				/* If we're not expecting a sub-algorithm but there's one
				   present, mark it as an error */
				if( algoIDmap[ i ].subAlgorithm != CRYPT_ALGO_NONE )
					return( CRYPT_ERROR );

			return( algoIDmap[ i ].algorithm );
			}

	return( CRYPT_ERROR );
	}

/* Map an algorithm and optional sub-algorithm to an OID.  These functions
   are almost identical, the only difference is that the one used for
   checking only doesn't throw an exception when it encounters an algorithm
   value that it can't encode as an OID */

static const BYTE *algorithmToOID( const CRYPT_ALGO_TYPE algorithm, 
								   const CRYPT_ALGO_TYPE subAlgorithm )
	{
	int i;

	for( i = 0; algoIDmap[ i ].algorithm != CRYPT_ALGO_NONE; i++ )
		if( algoIDmap[ i ].algorithm == algorithm && \
			algoIDmap[ i ].subAlgorithm == subAlgorithm )
			return( algoIDmap[ i ].oid );

	assert( NOTREACHED );
	return( NULL );	/* Get rid of compiler warning */
	}

static const BYTE *algorithmToOIDcheck( const CRYPT_ALGO_TYPE algorithm, 
										const CRYPT_ALGO_TYPE subAlgorithm )
	{
	int i;

	for( i = 0; algoIDmap[ i ].algorithm != CRYPT_ALGO_NONE; i++ )
		if( algoIDmap[ i ].algorithm == algorithm && \
			algoIDmap[ i ].subAlgorithm == subAlgorithm )
			return( algoIDmap[ i ].oid );

	return( NULL );
	}

int readOID( STREAM *stream, const BYTE *oid )
	{
	BYTE buffer[ MAX_OID_SIZE ];
	int dummy, status;

	status = readRawObject( stream, buffer, &dummy, MAX_OID_SIZE,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) || \
		memcmp( buffer, oid, sizeofOID( oid ) ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		status = CRYPT_ERROR_BADDATA;
		}

	return( status );
	}

int readOIDSelection( STREAM *stream, const OID_SELECTION *oidSelection, 
					  int *selection )
	{
	BYTE buffer[ MAX_OID_SIZE ];
	int length, oidEntry, status;

	/* Read the OID data */
	status = readRawObject( stream, buffer, &length, MAX_OID_SIZE,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );

	/* Try and find the entry for the OID */
	for( oidEntry = 0; oidSelection[ oidEntry ].oid != NULL; oidEntry++ )
		if( length == sizeofOID( oidSelection[ oidEntry ].oid ) && \
			!memcmp( buffer, oidSelection[ oidEntry ].oid, length ) )
			break;
	if( oidSelection[ oidEntry ].oid == NULL )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		status = CRYPT_ERROR_BADDATA;
		}
	if( selection != NULL )
		*selection = oidSelection[ oidEntry ].selection;
	
	return( status );
	}

/****************************************************************************
*																			*
*					EncryptionAlgorithmIdentifier Routines					*
*																			*
****************************************************************************/

/* EncryptionAlgorithmIdentifier parameters:

	aesXcbc, aesXofb: AES FIPS

		iv				OCTET STRING SIZE (16)

	aesXcfb: AES FIPS

		SEQUENCE {
			iv			OCTET STRING SIZE (16),
			noOfBits	INTEGER (128)
			}

	cast5cbc: RFC 2144
		SEQUENCE {
			iv			OCTET STRING DEFAULT 0,
			keyLen		INTEGER (128)
			}

	blowfishCBC, desCBC, desEDE3-CBC: Blowfish RFC/OIW
		iv				OCTET STRING SIZE (8)

	blowfishCFB, blowfishOFB, desCFB, desOFB: Blowfish RFC/OIW
		SEQUENCE {
			iv			OCTET STRING SIZE (8),
			noBits		INTEGER (64)
			}

	ideaCBC: Ascom Tech
		SEQUENCE {
			iv			OCTET STRING OPTIONAL
			}

	ideaCFB: Ascom Tech
		SEQUENCE {
			r	  [ 0 ]	INTEGER DEFAULT 64,
			k	  [ 1 ]	INTEGER DEFAULT 64,
			j	  [ 2 ]	INTEGER DEFAULT 64,
			iv	  [ 3 ]	OCTET STRING OPTIONAL
			}

	ideaOFB: Ascom Tech
		SEQUENCE {
			j			INTEGER DEFAULT 64,
			iv			OCTET STRING OPTIONAL
			}

	rc2CBC: RFC 2311
		SEQUENCE {
			rc2Param	INTEGER (58),	-- 128 bit key
			iv			OCTET STRING SIZE (8)
			}

	rc4: RFC 2311
		NULL

	rc5: RFC 2040
		SEQUENCE {
			version		INTEGER (16),
			rounds		INTEGER (12),
			blockSize	INTEGER (64),
			iv			OCTET STRING OPTIONAL
			}

	skipjackCBC: SDN.701
		SEQUENCE {
			iv			OCTET STRING
			}

   Because of the haphazard and arbitrary nature of encryption 
   AlgorithmIdentifier definitions, we can only handle the following 
   algorithm/mode combinations:

	AES ECB, CBC, CFB, OFB
	Blowfish ECB, CBC, CFB, OFB
	CAST128 CBC
	DES ECB, CBC, CFB, OFB
	3DES ECB, CBC, CFB, OFB
	IDEA ECB, CBC, CFB, OFB
	RC2 ECB, CBC
	RC4
	RC5 CBC
	Skipjack CBC */

/* Magic value to denote 128-bit RC2 keys */

#define RC2_KEYSIZE_MAGIC		58

/* Read an EncryptionAlgorithmIdentifier record */

static int readAlgoIDInfo( STREAM *stream, QUERY_INFO *queryInfo, 
						   const int tag )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	BYTE buffer[ MAX_OID_SIZE ];
	int length, bufferLength, cryptMode, status;

	/* Read the AlgorithmIdentifier header and OID */
	if( tag == DEFAULT_TAG )
		readSequence( stream, &length );
	else
		readConstructed( stream, &length, tag );
	status = readRawObject( stream, buffer, &bufferLength, MAX_OID_SIZE, 
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	if( ( cryptAlgo = oidToAlgorithm( buffer, &cryptMode ) ) == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTAVAIL );
	queryInfo->cryptAlgo = cryptAlgo;
	queryInfo->cryptMode = cryptMode;
	length -= bufferLength;

	/* Non-conventional-encryption algorithms will either have NULL 
	   parameters or none at all depending on which interpreation of which
	   standard the sender used, so if it's not a conventional encryption
	   algorithm we just skip any remaining parameter data and return */
	if( queryInfo->cryptAlgo < CRYPT_ALGO_FIRST_CONVENTIONAL || \
		queryInfo->cryptAlgo > CRYPT_ALGO_LAST_CONVENTIONAL )
		return( ( length > 0 ) ? sSkip( stream, length ) : CRYPT_OK );

	/* Read the algorithm parameters.  In theory we should do something with 
	   some of the values like the IV size parameter, but since the standard 
	   never explains what to do if it's something other than the algorithm 
	   block size (Left pad? Right pad? Sign-extend? Repeat the data?) it's 
	   safer not to do anything ("Never check for an error you don't know how 
	   to handle").  In any case there are no known cases of these strange 
	   values ever being used (probably because all existing software would 
	   break) so for now we just make sure they're present but otherwise 
	   ignore them */
	if( cryptAlgo == CRYPT_ALGO_CAST )
		{
		readSequence( stream, NULL );
		readOctetString( stream, queryInfo->iv, &queryInfo->ivLength, 
						 CRYPT_MAX_IVSIZE );
		return( readShortInteger( stream, NULL ) );
		}
	if( cryptAlgo == CRYPT_ALGO_AES || cryptAlgo == CRYPT_ALGO_DES || \
		cryptAlgo == CRYPT_ALGO_3DES || cryptAlgo == CRYPT_ALGO_BLOWFISH )
		{
		if( cryptMode == CRYPT_MODE_ECB )
			return( readNull( stream ) );
		if( ( cryptMode == CRYPT_MODE_CBC ) || \
			( cryptAlgo == CRYPT_ALGO_AES && cryptMode == CRYPT_MODE_OFB ) )
			return( readOctetString( stream, queryInfo->iv, 
									 &queryInfo->ivLength, CRYPT_MAX_IVSIZE ) );
		readSequence( stream, NULL );
		readOctetString( stream, queryInfo->iv, &queryInfo->ivLength, 
						 CRYPT_MAX_IVSIZE );
		return( readShortInteger( stream, NULL ) );
		}
	if( cryptAlgo == CRYPT_ALGO_IDEA )
		{
		int paramTag;

		if( cryptMode == CRYPT_MODE_ECB )
			return( readNull( stream ) );
		readSequence( stream, NULL );
		paramTag = peekTag( stream );
		if( cryptMode == CRYPT_MODE_CFB )
			{
			/* Skip the CFB r, k, and j parameters */
			while( paramTag == MAKE_CTAG_PRIMITIVE( 0 ) || \
				   paramTag == MAKE_CTAG_PRIMITIVE( 1 ) || \
				   paramTag == MAKE_CTAG_PRIMITIVE( 2 ) )
				{
				long value;

				status = readShortIntegerTag( stream, &value, paramTag );
				if( cryptStatusError( status ) || value != 64 )
					return( CRYPT_ERROR_NOTAVAIL );
				paramTag = peekTag( stream );
				}
			return( readOctetStringTag( stream, queryInfo->iv, 
										&queryInfo->ivLength, 
										CRYPT_MAX_IVSIZE, 3 ) );
			}
		if( cryptMode == CRYPT_MODE_OFB && paramTag == BER_INTEGER )
			{
			long value;

			/* Skip the OFB j parameter */
			status = readShortInteger( stream, &value );
			if( cryptStatusError( status ) || value != 64 )
				return( CRYPT_ERROR_NOTAVAIL );
			}
		return( readOctetString( stream, queryInfo->iv, &queryInfo->ivLength, 
								 CRYPT_MAX_IVSIZE ) );
		}
	if( cryptAlgo == CRYPT_ALGO_RC2 )
		{
		/* In theory we should check that the parameter value == 
		   RC2_KEYSIZE_MAGIC (corresponding to a 128-bit key) but in practice 
		   this doesn't really matter, we just use whatever we find inside
		   the PKCS #1 padding */
		readSequence( stream, NULL );
		if( cryptMode != CRYPT_MODE_CBC )
			return( readShortInteger( stream, NULL ) );
		readShortInteger( stream, NULL );
		return( readOctetString( stream, queryInfo->iv, &queryInfo->ivLength, 
								 CRYPT_MAX_IVSIZE ) );
		}
	if( cryptAlgo == CRYPT_ALGO_RC4 )
		return( readNull( stream ) );
	if( cryptAlgo == CRYPT_ALGO_RC5 )
		{
		long val1, val2, val3;

		readSequence( stream, NULL );
		readShortInteger( stream, &val1 );			/* Version */
		readShortInteger( stream, &val2 );			/* Rounds */
		status = readShortInteger( stream, &val3 );	/* Block size */
		if( cryptStatusError( status ) || \
			val1 != 16 || val2 != 12 || val3 != 64 )
			/* This algorithm makes enough of a feature of its variable
			   parameters that we do actually check to make sure they're
			   sensible since it may just be possible that someone playing
			   with an implementation decides to use weird values */
			return( CRYPT_ERROR_NOTAVAIL );
		return( readOctetString( stream, queryInfo->iv, &queryInfo->ivLength, 
								 CRYPT_MAX_IVSIZE ) );
		}
	if( cryptAlgo == CRYPT_ALGO_SKIPJACK )
		{
		readSequence( stream, NULL );
		return( readOctetString( stream, queryInfo->iv, 
								 &queryInfo->ivLength, CRYPT_MAX_IVSIZE ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Write an EncryptionAlgorithmIdentifier record */

static int writeContextCryptAlgoID( STREAM *stream, 
									const CRYPT_CONTEXT iCryptContext )
	{
	const BYTE *oid;
	BYTE iv[ CRYPT_MAX_IVSIZE ];
	CRYPT_ALGO_TYPE algorithm;
	CRYPT_MODE_TYPE mode;
	int oidSize, ivSize = 0, sizeofIV = 0, status;

	/* Extract the information we need to write the AlgorithmIdentifier */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
								  &mode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) && !isStreamCipher( algorithm ) && \
		needsIV( mode ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, iv, CRYPT_MAX_IVSIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_IV );
		if( status == CRYPT_ERROR_NOTINITED && sIsNullStream( stream ) )
			/* If we're just doing a length check there may not be an IV set
			   yet, so we just use dummy data */
			status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
									  &ivSize, CRYPT_CTXINFO_IVSIZE );
		ivSize = msgData.length;
		sizeofIV = ( int ) sizeofObject( ivSize );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( ( oid = algorithmToOIDcheck( algorithm, 
									 ( CRYPT_ALGO_TYPE ) mode ) ) == NULL )
		/* Some algorithm+mode combinations can't be encoded using the
		   oddball collection of PKCS #7 OIDs, the best we can do is return
		   a CRYPT_ERROR_NOTAVAIL */
		return( CRYPT_ERROR_NOTAVAIL );
	oidSize = sizeofOID( oid );

	/* Write algorithm-specific OID parameters */
	if( algorithm == CRYPT_ALGO_CAST )
		{
		const int paramSize = sizeofIV + sizeofShortInteger( 128 );

		writeSequence( stream, oidSize + ( int ) sizeofObject( paramSize ) );
		swrite( stream, oid, oidSize );
		writeSequence( stream, paramSize );
		writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
		return( writeShortInteger( stream, 128, DEFAULT_TAG ) );
		}
	if( algorithm == CRYPT_ALGO_AES || algorithm == CRYPT_ALGO_DES || \
		algorithm == CRYPT_ALGO_3DES || algorithm == CRYPT_ALGO_BLOWFISH )
		{
		const int noBits = ( algorithm == CRYPT_ALGO_AES ) ? 128 : 64;
		const int paramSize = ( mode == CRYPT_MODE_ECB ) ? sizeofNull() : \
			( ( mode == CRYPT_MODE_CBC ) || \
			  ( algorithm == CRYPT_ALGO_AES && mode == CRYPT_MODE_OFB ) ) ? \
			  sizeofIV : \
			  ( int ) sizeofObject( sizeofIV + sizeofShortInteger( noBits ) );

		writeSequence( stream, oidSize + paramSize );
		if( algorithm == CRYPT_ALGO_AES )
			{
			int keySize;

			/* AES uses a bizarre encoding in which the last byte of the OID
			   jumps in steps of 20 depending on the key size, so we adjust
			   the OID we actually write based on the key size (it's 
			   extremely unlikely that any implementation cares about this 
			   since the size information is always communicated anderswhere, 
			   but we do it just in case) */
			krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, &keySize, 
							 CRYPT_CTXINFO_KEYSIZE );
			swrite( stream, oid, oidSize - 1 );
			sputc( stream, oid[ oidSize - 1 ] + \
						   ( keySize == 16 ? 0 : keySize == 24 ? 20 : 40 ) );
			}
		else
			swrite( stream, oid, oidSize );
		if( mode == CRYPT_MODE_ECB )
			return( writeNull( stream, DEFAULT_TAG ) );
		if( ( mode == CRYPT_MODE_CBC ) || \
			( algorithm == CRYPT_ALGO_AES && mode == CRYPT_MODE_OFB ) )
			return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
		writeSequence( stream, sizeofIV + sizeofShortInteger( noBits ) );
		writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
		return( writeShortInteger( stream, noBits, DEFAULT_TAG ) );
		}
	if( algorithm == CRYPT_ALGO_IDEA )
		{
		const int paramSize = ( mode == CRYPT_MODE_ECB ) ? \
							  sizeofNull() : ( int ) sizeofObject( sizeofIV );

		writeSequence( stream, oidSize + paramSize );
		swrite( stream, oid, oidSize );
		if( mode == CRYPT_MODE_ECB )
			return( writeNull( stream, DEFAULT_TAG ) );
		writeSequence( stream, sizeofIV );
		return( writeOctetString( stream, iv, ivSize, \
							( mode == CRYPT_MODE_CFB ) ? 3 : DEFAULT_TAG ) );
		}
	if( algorithm == CRYPT_ALGO_RC2 )
		{
		const int paramSize = ( ( mode == CRYPT_MODE_ECB ) ? 0 : sizeofIV ) +
							  sizeofShortInteger( RC2_KEYSIZE_MAGIC );

		writeSequence( stream, oidSize + ( int ) sizeofObject( paramSize ) );
		swrite( stream, oid, oidSize );
		writeSequence( stream, paramSize );
		status = writeShortInteger( stream, RC2_KEYSIZE_MAGIC, DEFAULT_TAG );
		if( mode == CRYPT_MODE_CBC )
			return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
		return( status );
		}
	if( algorithm == CRYPT_ALGO_RC4 )
		{
		writeSequence( stream, oidSize + sizeofNull() );
		swrite( stream, oid, oidSize );
		return( writeNull( stream, DEFAULT_TAG ) );
		}
	if( algorithm == CRYPT_ALGO_RC5 )
		{
		const int paramSize = sizeofShortInteger( 16 ) +
					sizeofShortInteger( 12 ) + sizeofShortInteger( 64 ) +
					sizeofIV;

		writeSequence( stream, oidSize + ( int ) sizeofObject( paramSize ) );
		swrite( stream, oid, oidSize );
		writeSequence( stream, paramSize );
		writeShortInteger( stream, 16, DEFAULT_TAG );	/* Version */
		writeShortInteger( stream, 12, DEFAULT_TAG );	/* Rounds */
		writeShortInteger( stream, 64, DEFAULT_TAG );	/* Block size */
		return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
		}
	if( algorithm == CRYPT_ALGO_SKIPJACK )
		{
		writeSequence( stream, oidSize + ( int ) sizeofObject( sizeofIV ) );
		swrite( stream, oid, oidSize );
		writeSequence( stream, sizeofIV );
		return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*							AlgorithmIdentifier Routines					*
*																			*
****************************************************************************/

/* Because AlgorithmIdentifier's are only defined for a subset of the
   algorithms that cryptlib supports, we have to check that the algorithm
   and mode being used can be represented in encoded data before we try to
   do anything with it */

BOOLEAN checkAlgoID( const CRYPT_ALGO_TYPE algorithm, 
					 const CRYPT_MODE_TYPE mode )
	{
	return( ( algorithmToOIDcheck( algorithm, \
						( CRYPT_ALGO_TYPE ) mode ) != NULL ) ? TRUE : FALSE );
	}

/* Determine the size of an AlgorithmIdentifier record */

int sizeofAlgoIDex( const CRYPT_ALGO_TYPE algorithm, 
					const CRYPT_ALGO_TYPE subAlgorithm,
					const int extraLength )
	{
	return( ( int ) sizeofObject( \
				sizeofOID( algorithmToOID( algorithm, subAlgorithm ) ) + \
				( extraLength ? extraLength : sizeofNull() ) ) );
	}

int sizeofAlgoID( const CRYPT_ALGO_TYPE algorithm )
	{
	return( sizeofAlgoIDex( algorithm, CRYPT_ALGO_NONE, 0 ) );
	}

/* Write an AlgorithmIdentifier record */

int writeAlgoIDex( STREAM *stream, const CRYPT_ALGO_TYPE algorithm,
				   const CRYPT_ALGO_TYPE subAlgorithm, const int extraLength )
	{
	const BYTE *oid = algorithmToOID( algorithm, subAlgorithm );
	const int oidSize = sizeofOID( oid );

	/* Write the AlgorithmIdentifier field */
	writeSequence( stream, oidSize + \
				   ( extraLength ? extraLength : sizeofNull() ) );
	swrite( stream, oid, oidSize );
	if( !extraLength )
		/* No extra parameters so we need to write a NULL */
		writeNull( stream, DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

int writeAlgoID( STREAM *stream, const CRYPT_ALGO_TYPE algorithm  )
	{
	return( writeAlgoIDex( stream, algorithm, CRYPT_ALGO_NONE, 0 ) );
	}

/* Read an AlgorithmIdentifier record */

int readAlgoIDex( STREAM *stream, CRYPT_ALGO_TYPE *algorithm, 
				  CRYPT_ALGO_TYPE *subAlgorithm, int *extraLength )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	BYTE buffer[ MAX_OID_SIZE ];
	int bufferLength, cryptSubAlgo, length, status;

	/* Clear the result fields */
	if( algorithm != NULL )
		*algorithm = CRYPT_ALGO_NONE;
	if( subAlgorithm != NULL )
		*subAlgorithm = CRYPT_ALGO_NONE;
	if( extraLength != NULL )
		*extraLength = 0;

	/* Determine the algorithm information based on the AlgorithmIdentifier
	   field */
	readSequence( stream, &length );
	status = readRawObject( stream, buffer, &bufferLength, MAX_OID_SIZE,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	length -= bufferLength;
	if( ( cryptAlgo = oidToAlgorithm( buffer, &cryptSubAlgo ) ) == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTAVAIL );
	if( algorithm != NULL )
		*algorithm = cryptAlgo;
	if( subAlgorithm != NULL )
		*subAlgorithm = cryptSubAlgo;

	/* If the user isn't interested in the algorithm parameters, skip them */
	if( extraLength == NULL )
		return( ( length > 0 ) ? sSkip( stream, length ) : CRYPT_OK );

	/* Handle any remaining parameters */
	if( length == sizeofNull() )
		return( readNull( stream ) );
	*extraLength = ( int ) length;
	return( CRYPT_OK );
	}

int readAlgoID( STREAM *stream, CRYPT_ALGO_TYPE *algorithm )
	{
	return( readAlgoIDex( stream, algorithm, NULL, NULL ) );
	}

/* Determine the size of an AlgorithmIdentifier record from an encryption
   context */

int sizeofContextAlgoID( const CRYPT_CONTEXT iCryptContext,
						 const CRYPT_ALGO_TYPE subAlgorithm, 
						 const int flags )
	{
	int cryptAlgo, status;

	/* If it's a standard write, determine how large the algoID and 
	   parameters are.  Because this is a rather complex operation, the
	   easiest way to do it is to write to a null stream and get its
	   size */
	if( flags == ALGOID_FLAG_NONE )
		{
		STREAM nullStream;

		sMemOpen( &nullStream, NULL, 0 );
		status = writeContextAlgoID( &nullStream, iCryptContext, 
									 subAlgorithm, ALGOID_FLAG_NONE );
		if( cryptStatusOK( status ) )
			status = stell( &nullStream );
		sMemClose( &nullStream );
		return( status );
		}

	assert( flags == ALGOID_FLAG_ALGOID_ONLY );

	/* Write the algoID only */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	return( sizeofAlgoIDex( cryptAlgo, subAlgorithm, 0 ) );
	}

/* Write an AlgorithmIdentifier record from an encryption context */

int writeContextAlgoID( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						const CRYPT_ALGO_TYPE subAlgorithm, 
						const int flags )
	{
	int cryptAlgo, status;

	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	if( flags & ALGOID_FLAG_ALGOID_ONLY )
		return( writeAlgoIDex( stream, cryptAlgo, subAlgorithm, 0 ) );

	/* If we're writing parameters such as key and block sizes and IV 
	   alongside the algorithm identifier, it has to be a conventional
	   context */
	assert( subAlgorithm == CRYPT_ALGO_NONE );
	assert( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
			cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL );

	return( writeContextCryptAlgoID( stream, iCryptContext ) );
	}

/* Turn an AlgorithmIdentifier into a hash/encryption context */

int readContextAlgoID( STREAM *stream, CRYPT_CONTEXT *iCryptContext,
					   QUERY_INFO *queryInfo, const int tag )
	{
	QUERY_INFO localQueryInfo, *queryInfoPtr = ( queryInfo == NULL ) ? \
											   &localQueryInfo : queryInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	/* Read the algorithm info.  If we're not creating a context from the
	   info, we're done */
	if( iCryptContext != NULL )
		*iCryptContext = CRYPT_ERROR;
	status = readAlgoIDInfo( stream, queryInfoPtr, tag );
	if( cryptStatusError( status ) || iCryptContext == NULL )
		{
		if( status == CRYPT_ERROR_BADDATA || status == CRYPT_ERROR_UNDERFLOW )
			/* It's a stream-related error, make it persistent */
			sSetError( stream, status );
		return( status );
		}

	/* Create the object from it */
	setMessageCreateObjectInfo( &createInfo, queryInfoPtr->cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	if( queryInfoPtr->cryptAlgo > CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		/* If it's not a conventional encryption algorithm, we're done */
		*iCryptContext = createInfo.cryptHandle;
		return( CRYPT_OK );
		}
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  &queryInfoPtr->cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) && \
		!isStreamCipher( queryInfoPtr->cryptAlgo ) )
		{
		RESOURCE_DATA msgData;
		int ivLength;

		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_GETATTRIBUTE, &ivLength, 
								  CRYPT_CTXINFO_IVSIZE );
		setMessageData( &msgData, queryInfoPtr->iv, 
						min( ivLength, queryInfoPtr->ivLength ) );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( createInfo.cryptHandle, 
									  IMESSAGE_SETATTRIBUTE_S, &msgData, 
									  CRYPT_CTXINFO_IV );
		}
	if( cryptStatusError( status ) )
		{
		/* If there's an error in the parameters stored with the key we'll 
		   get an arg or attribute error when we try to set the attribute so 
		   we translate it into an error code which is appropriate for the 
		   situation.  In addition since this is (arguably) a stream format
		   error (the data read from the stream is invalid), we also set the
		   stream status */
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( cryptArgError( status ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			status = CRYPT_ERROR_BADDATA;
			}
		}
	else
		*iCryptContext = createInfo.cryptHandle;
	return( status );
	}

/****************************************************************************
*																			*
*							Message Digest Routines							*
*																			*
****************************************************************************/

/* Read/write a message digest value.  This is another one of those oddball
   functions which is present here because it's the least inappropriate place
   to put it */

int writeMessageDigest( STREAM *stream, const CRYPT_ALGO_TYPE hashAlgo, 
						const void *hash, const int hashSize )
	{
	writeSequence( stream, sizeofAlgoID( hashAlgo ) + \
				   ( int ) sizeofObject( hashSize ) );
	writeAlgoID( stream, hashAlgo );
	return( writeOctetString( stream, hash, hashSize, DEFAULT_TAG ) );
	}

int readMessageDigest( STREAM *stream, CRYPT_ALGO_TYPE *hashAlgo, void *hash, 
					   int *hashSize )
	{
	readSequence( stream, NULL );
	readAlgoID( stream, hashAlgo );
	return( readOctetString( stream, hash, hashSize, CRYPT_MAX_HASHSIZE ) );
	}

/****************************************************************************
*																			*
*								CMS Header Routines							*
*																			*
****************************************************************************/

/* Read and write CMS headers */

int readCMSheader( STREAM *stream, const OID_SELECTION *oidSelection,
				   long *dataSize, const BOOLEAN isInnerHeader )
	{
	BOOLEAN isData = FALSE;
	BYTE oid[ MAX_OID_SIZE ];
	long totalLength, value;
	int length, oidEntry, status;

	/* Clear return value */
	if( dataSize != NULL )
		*dataSize = 0;

	/* Read the outer SEQUENCE and OID and try and find the entry for the 
	   OID.  Note that we can't use a normal readSequence() here since the 
	   data length could be much longer than the maximum allowed in the 
	   readSequence() sanity check.  In addition we can't use 
	   readOIDSelection() either since we have to identify and handle data 
	   vs. non-data content in different ways */
	readLongSequence( stream, &totalLength );
	status = readRawObject( stream, oid, &length, MAX_OID_SIZE,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	for( oidEntry = 0; oidSelection[ oidEntry ].oid != NULL; oidEntry++ )
		if( length == sizeofOID( oidSelection[ oidEntry ].oid ) && \
			!memcmp( oid, oidSelection[ oidEntry ].oid, length ) )
			break;
	if( oidSelection[ oidEntry ].oid == NULL )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	/* If the content type is data, the content is an OCTET STRING rather
	   than a SEQUENCE so we remember the type for later */
	if( length == sizeofOID( OID_CMS_DATA ) && \
		!memcmp( oid, OID_CMS_DATA, sizeofOID( OID_CMS_DATA ) ) )
		isData = TRUE;

	/* Some Microsoft software produces an indefinite encoding for a single
	   OID so we have to check for this */
	if( totalLength == CRYPT_UNUSED )
		{
		status = checkEOC( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( status == TRUE )
			/* We've seen EOC octets, the length is the overall data 
			   length */
			totalLength = length;
		}

	/* If the content is supplied externally (for example with a detached
	   sig), there won't be any content present */
	if( totalLength == length )
		{
		if( dataSize != NULL )
			*dataSize = 0;
		}
	else
		{
		int tag;

		/* Read the content [0] tag and OCTET STRING/SEQUENCE (this requires 
		   some special-case handling, see the comment in writeCMSHeader() 
		   for more details) */
		status = readLongConstructed( stream, NULL, 0 );
		if( cryptStatusError( status ) )
			return( status );
		tag = peekTag( stream );
		if( isData )
			{
			/* It's pure data content, it must be an OCTET STRING */
			if( tag != BER_OCTETSTRING && \
				tag != ( BER_OCTETSTRING | BER_CONSTRUCTED ) )
				status = CRYPT_ERROR_BADDATA;
			}
		else
			if( isInnerHeader )
				{
				/* It's an inner header, it should be an OCTET STRING but 
				   alternative interpretations are possible based on the 
				   PKCS #7 definition of inner content */
				if( tag != BER_OCTETSTRING && \
					tag != ( BER_OCTETSTRING | BER_CONSTRUCTED ) && \
					tag != BER_SEQUENCE )
					status = CRYPT_ERROR_BADDATA;
				}
			else
				/* It's an outer header containing other than data, it must 
				   be a SEQUENCE */
				if( tag != BER_SEQUENCE )
					status = CRYPT_ERROR_BADDATA;
		if( cryptStatusError( status ) )
			{
			sSetError( stream, status );
			return( status );
			}
		status = readLongGenericHole( stream, &totalLength, tag );
		if( cryptStatusError( status ) )
			return( status );
		if( dataSize != NULL )
			*dataSize = totalLength;
		}

	/* If it's not data in an OCTET STRING, check the version number of the
	   content if required */
	if( !isData && oidSelection[ oidEntry ].minVersion != CRYPT_UNUSED )
		{
		readShortInteger( stream, &value );
		if( value < oidSelection[ oidEntry ].minVersion || \
			value > oidSelection[ oidEntry ].maxVersion )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
		}

	return( sStatusOK( stream ) ? oidSelection[ oidEntry ].selection : \
								  sGetStatus( stream ) );
	}

int writeCMSheader( STREAM *stream, const BYTE *oid, const long dataSize,
					const BOOLEAN isInnerHeader )
	{
	BOOLEAN isOctetString = ( isInnerHeader || \
							  ( sizeofOID( oid ) == 11 && \
							  !memcmp( oid, OID_CMS_DATA, 11 ) ) ) ? \
							TRUE : FALSE;

	/* The handling of the wrapper type for the content is rather complex.
	   If it's an outer header, it's an OCTET STRING for data and a SEQUENCE
	   for everything else.  If it's an inner header it usually follows the
	   same rule, however for signed data the content was changed from

		content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL

	   in PKCS #7 to

		eContent [0] EXPLICIT OCTET STRING OPTIONAL

	   for CMS (it was always an OCTET STRING for encrypted data).  To
	   complicate things, there are some older implementations based on the 
	   PKCS #7 interpretation that use a SEQUENCE (namely AuthentiCode).
	   To resolve this, we use an OCTET STRING for inner content unless the
	   content type is spcIndirectDataContext */
	if( isInnerHeader && sizeofOID( oid ) == 12 && \
		!memcmp( oid, OID_MS_SPCINDIRECTDATACONTEXT, 12 ) )
		isOctetString = FALSE;

	/* If a size is given, write the definite form */
	if( dataSize != CRYPT_UNUSED )
		{
		writeSequence( stream, sizeofOID( oid ) + ( ( dataSize ) ? \
					   ( int ) sizeofObject( sizeofObject( dataSize ) ) : 0 ) );
		writeOID( stream, oid );
		if( !dataSize )
			return( CRYPT_OK );	/* No content, exit */
		writeConstructed( stream, sizeofObject( dataSize ), 0 );
		if( isOctetString )
			return( writeOctetStringHole( stream, dataSize, DEFAULT_TAG ) );
		return( writeSequence( stream, dataSize ) );
		}

	/* No size given, write the indefinite form */
	writeSequenceIndef( stream );
	writeOID( stream, oid );
	writeCtag0Indef( stream );
	return( isOctetString ? writeOctetStringIndef( stream ) : \
							writeSequenceIndef( stream ) );
	}

/* Read and write an encryptedContentInfo header.  The inner content may be
   implicitly or explicitly tagged depending on the exact content type */

int sizeofCMSencrHeader( const BYTE *contentOID, const long dataSize,
						 const CRYPT_CONTEXT iCryptContext )
	{
	STREAM nullStream;
	int status, cryptInfoSize;

	/* Determine the encoded size of the AlgorithmIdentifier */
	sMemOpen( &nullStream, NULL, 0 );
	status = writeContextCryptAlgoID( &nullStream, iCryptContext );
	cryptInfoSize = stell( &nullStream );
	sMemClose( &nullStream );
	if( cryptStatusError( status ) )
		return( status );

	/* Calculate encoded size of SEQUENCE + OID + AlgoID + [0] for the
	   definite or indefinite forms */
	if( dataSize != CRYPT_UNUSED )
		return( ( int ) ( sizeofObject( sizeofOID( contentOID ) + \
				cryptInfoSize + sizeofObject( dataSize ) ) - dataSize ) );
	return( 2 + sizeofOID( contentOID ) + cryptInfoSize + 2 );
	}

int readCMSencrHeader( STREAM *stream, const OID_SELECTION *oidSelection,
					   CRYPT_CONTEXT *iCryptContext, QUERY_INFO *queryInfo )
	{
	QUERY_INFO localQueryInfo, *queryInfoPtr = ( queryInfo == NULL ) ? \
											   &localQueryInfo : queryInfo;
	long length;
	int oidEntry, tag, status;

	/* Clear the return values */
	if( iCryptContext != NULL )
		*iCryptContext = CRYPT_ERROR;
	memset( queryInfoPtr, 0, sizeof( QUERY_INFO ) );

	/* Read the outer SEQUENCE and OID.  Note that we can't use a normal
	   readSequence() here since the data length could be much longer 
	   than the maximum allowed in the readSequence() sanity check */
	readLongSequence( stream, NULL );
	status = readOIDSelection( stream, oidSelection, &oidEntry );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the AlgorithmIdentifier.  This can return non-stream-related
	   errors so if there's an error at this point we exit immediately */
	status = readContextAlgoID( stream, iCryptContext, queryInfoPtr, 
								DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the content [0] tag, which may be either primitive or constructed
	   depending on the content */
	tag = peekTag( stream );
	status = readLongGenericHole( stream, &length, tag );
	if( cryptStatusOK( status ) && \
		( tag != MAKE_CTAG( 0 ) && tag != MAKE_CTAG_PRIMITIVE( 0 ) ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		{
		if( iCryptContext != NULL )
			krnlSendNotifier( *iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	queryInfoPtr->size = length;

	return( oidEntry );
	}

int writeCMSencrHeader( STREAM *stream, const BYTE *contentOID,
						const long dataSize,
						const CRYPT_CONTEXT iCryptContext )
	{
	STREAM nullStream;
	int cryptInfoSize, status;

	/* Determine the encoded size of the AlgorithmIdentifier */
	sMemOpen( &nullStream, NULL, 0 );
	status = writeContextCryptAlgoID( &nullStream, iCryptContext );
	cryptInfoSize = stell( &nullStream );
	sMemClose( &nullStream );
	if( cryptStatusError( status ) )
		return( status );

	/* If a size is given, write the definite form */
	if( dataSize != CRYPT_UNUSED )
		{
		writeSequence( stream, sizeofOID( contentOID ) + cryptInfoSize + \
					   ( int ) sizeofObject( dataSize ) );
		writeOID( stream, contentOID );
		status = writeContextCryptAlgoID( stream, iCryptContext );
		writeOctetStringHole( stream, dataSize, MAKE_CTAG_PRIMITIVE( 0 ) );
		return( status );
		}

	/* No size given, write the indefinite form */
	writeSequenceIndef( stream );
	writeOID( stream, contentOID );
	status = writeContextCryptAlgoID( stream, iCryptContext );
	writeCtag0Indef( stream );
	return( status );
	}
