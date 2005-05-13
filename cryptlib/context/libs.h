/****************************************************************************
*																			*
*					cryptlib Crypto Libraries Header File 					*
*					  Copyright Peter Gutmann 1992-2003						*
*																			*
****************************************************************************/

#ifndef _LIBS_DEFINED

#define _LIBS_DEFINED

/* The parameters of most encryption algorithms are traditionally specified
   in bits, so we define a shorter form of the bitsToBytes() macro to reduce
   the amount of blackspace */

#define bits(x)	bitsToBytes(x)

/* The CONTEXT_INFO structure is only visible inside modules that have access
   to context internals, if we use it anywhere else we just treat it as a
   generic void * */

#ifndef _CRYPTCTX_DEFINED
  #define CONTEXT_INFO	void
#endif /* _CRYPTCTX_DEFINED */

/* If we haven't got the capability info defined yet (from a prior include 
   of capabil.h via context.h), pull it in explicitly */

#ifndef _CRYPTCAP_DEFINED
  #if defined( INC_ALL )
	#include "capabil.h"
  #elif defined( INC_CHILD )
	#include "../device/capabil.h"
  #else
	#include "device/capabil.h"
  #endif /* Compiler-specific includes */
#endif /* _CRYPTCAP_DEFINED */

/* The functions used to implement the Blowfish encryption routines */

int blowfishSelfTest( void );
int blowfishGetInfo( const CAPABILITY_INFO_TYPE type, 
					 void *varParam, const int constParam );
int blowfishInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int blowfishEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int blowfishDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int blowfishEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int blowfishDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int blowfishEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int blowfishDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int blowfishEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int blowfishDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the CAST-128 encryption routines */

int castSelfTest( void );
int castGetInfo( const CAPABILITY_INFO_TYPE type, 
				 void *varParam, const int constParam );
int castInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int castEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int castDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int castEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int castDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int castEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int castDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int castEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int castDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the DES encryption routines */

int desSelfTest( void );
int desGetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam );
int desInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int desEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int desDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int desEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int desDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int desEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int desDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int desEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int desDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the triple DES encryption routines */

int des3SelfTest( void );
int des3GetInfo( const CAPABILITY_INFO_TYPE type, 
				 void *varParam, const int constParam );
int des3InitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int des3EncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int des3DecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int des3EncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int des3DecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int des3EncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int des3DecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int des3EncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int des3DecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the IDEA encryption routines */

int ideaSelfTest( void );
int ideaGetInfo( const CAPABILITY_INFO_TYPE type, 
				 void *varParam, const int constParam );
int ideaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int ideaEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int ideaDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int ideaEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int ideaDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int ideaEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int ideaDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int ideaEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int ideaDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement RC2 encryption routines */

int rc2SelfTest( void );
int rc2GetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam );
int rc2InitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int rc2EncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc2DecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc2EncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc2DecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc2EncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc2DecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc2EncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc2DecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the RC4 encryption routines */

int rc4SelfTest( void );
int rc4GetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam );
int rc4InitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int rc4Encrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement RC5 encryption routines */

int rc5SelfTest( void );
int rc5GetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam );
int rc5InitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int rc5EncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc5DecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc5EncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc5DecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc5EncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc5DecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc5EncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rc5DecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the AES encryption routines */

int aesSelfTest( void );
int aesGetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam );
int aesInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int aesEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int aesDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int aesEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int aesDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int aesEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int aesDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int aesEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int aesDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the Skipjack encryption routines */

int skipjackSelfTest( void );
int skipjackGetInfo( const CAPABILITY_INFO_TYPE type, 
					 void *varParam, const int constParam );
int skipjackInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int skipjackEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int skipjackDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int skipjackEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int skipjackDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int skipjackEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int skipjackDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int skipjackEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int skipjackDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the Diffie-Hellman key exchange routines */

int dhSelfTest( void );
int dhInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int dhGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits );
int dhEncrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int dhDecrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the DSA encryption routines */

int dsaSelfTest( void );
int dsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int dsaGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits );
int dsaSign( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int dsaSigCheck( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the Elgamal encryption routines */

int elgamalSelfTest( void );
int elgamalInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int elgamalGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits );
int elgamalEncrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int elgamalDecrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the RSA encryption routines */

int rsaSelfTest( void );
int rsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int rsaGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits );
int rsaEncrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );
int rsaDecrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the MD2 hash routines */

int md2SelfTest( void );
int md2GetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam );
int md2Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the MD4 hash routines */

int md4SelfTest( void );
int md4GetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam );
int md4Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the MD5 hash routines */

int md5SelfTest( void );
int md5GetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam );
int md5Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the RIPEMD-160 hash routines */

int ripemd160SelfTest( void );
int ripemd160GetInfo( const CAPABILITY_INFO_TYPE type, 
					  void *varParam, const int constParam );
int ripemd160Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the SHA1 hash routines */

int shaSelfTest( void );
int shaGetInfo( const CAPABILITY_INFO_TYPE type, 
				void *varParam, const int constParam );
int shaHash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the SHA2 hash routines */

int sha2SelfTest( void );
int sha2GetInfo( const CAPABILITY_INFO_TYPE type, 
				 void *varParam, const int constParam );
int sha2Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the HMAC-MD5 MAC routines */

int hmacMD5SelfTest( void );
int hmacMD5GetInfo( const CAPABILITY_INFO_TYPE type, 
					void *varParam, const int constParam );
int hmacMD5InitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int hmacMD5Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the HMAC-RIPEMD-160 MAC routines */

int hmacRIPEMD160SelfTest( void );
int hmacRIPEMD160GetInfo( const CAPABILITY_INFO_TYPE type, 
						  void *varParam, const int constParam );
int hmacRIPEMD160InitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int hmacRIPEMD160Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

/* The functions used to implement the HMAC-SHA MAC routines */

int hmacSHASelfTest( void );
int hmacSHAGetInfo( const CAPABILITY_INFO_TYPE type, 
					void *varParam, const int constParam );
int hmacSHAInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
int hmacSHAHash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int length );

#endif /* _LIBS_DEFINED */
