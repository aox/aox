/****************************************************************************
*																			*
*					cryptlib Diffie-Hellman Key Exchange Routines			*
*						Copyright Peter Gutmann 1995-2002					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "libs.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/context.h"
  #include "libs.h"
#else
  #include "crypt.h"
  #include "misc/context.h"
  #include "libs/libs.h"
#endif /* Compiler-specific includes */

/* The DH key exchange process is somewhat complex because there are two
   phases involved for both sides, an "export" and an "import" phase, and 
   they have to be performed in the correct order.  The sequence of 
   operations is:

	A.load:		set p, g from fixed or external values
				x(A) = rand, x s.t. 0 < x < q-1

	A.export	y(A) = g^x(A) mod p		error if y != 0 at start
				output = y(A)

	B.load		read p, g / set p, g from external values
				x(B) = rand, x s.t. 0 < x < q-1

	B.import	y(A) = input
				z = y(A)^x(B) mod p

	B.export	y(B) = g^x(B) mod p		error if y != 0 at start
				output = y(B)

	A.import	y(B) = input
				z = y(B)^x(A) mod p

   Note that we have to set x when we load p and g because otherwise we'd
   have to set x(A) on export and x(B) on import, which is tricky since the
   DH code doesn't know whether it's working with A or B */

/****************************************************************************
*																			*
*								Algorithm Self-test							*
*																			*
****************************************************************************/

/* Test the Diffie-Hellman implementation using the sample key from FIPS 186.
   Because a lot of the high-level encryption routines don't exist yet, we
   cheat a bit and set up a dummy encryption context with just enough
   information for the following code to work */

typedef struct {
	const int pLen; const BYTE p[ 64 ];
	const int qLen; const BYTE q[ 20 ];
	const int gLen; const BYTE g[ 64 ];
	const int xLen; const BYTE x[ 20 ];
	const int yLen; const BYTE y[ 64 ];
	} DLP_PRIVKEY;

static const FAR_BSS DLP_PRIVKEY dlpTestKey = {
	/* p */
	64,
	{ 0x8D, 0xF2, 0xA4, 0x94, 0x49, 0x22, 0x76, 0xAA,
	  0x3D, 0x25, 0x75, 0x9B, 0xB0, 0x68, 0x69, 0xCB,
	  0xEA, 0xC0, 0xD8, 0x3A, 0xFB, 0x8D, 0x0C, 0xF7,
	  0xCB, 0xB8, 0x32, 0x4F, 0x0D, 0x78, 0x82, 0xE5,
	  0xD0, 0x76, 0x2F, 0xC5, 0xB7, 0x21, 0x0E, 0xAF,
	  0xC2, 0xE9, 0xAD, 0xAC, 0x32, 0xAB, 0x7A, 0xAC,
	  0x49, 0x69, 0x3D, 0xFB, 0xF8, 0x37, 0x24, 0xC2,
	  0xEC, 0x07, 0x36, 0xEE, 0x31, 0xC8, 0x02, 0x91 },
	/* q */
	20,
	{ 0xC7, 0x73, 0x21, 0x8C, 0x73, 0x7E, 0xC8, 0xEE,
	  0x99, 0x3B, 0x4F, 0x2D, 0xED, 0x30, 0xF4, 0x8E,
	  0xDA, 0xCE, 0x91, 0x5F },
	/* g */
	64,
	{ 0x62, 0x6D, 0x02, 0x78, 0x39, 0xEA, 0x0A, 0x13,
	  0x41, 0x31, 0x63, 0xA5, 0x5B, 0x4C, 0xB5, 0x00,
	  0x29, 0x9D, 0x55, 0x22, 0x95, 0x6C, 0xEF, 0xCB,
	  0x3B, 0xFF, 0x10, 0xF3, 0x99, 0xCE, 0x2C, 0x2E,
	  0x71, 0xCB, 0x9D, 0xE5, 0xFA, 0x24, 0xBA, 0xBF,
	  0x58, 0xE5, 0xB7, 0x95, 0x21, 0x92, 0x5C, 0x9C,
	  0xC4, 0x2E, 0x9F, 0x6F, 0x46, 0x4B, 0x08, 0x8C,
	  0xC5, 0x72, 0xAF, 0x53, 0xE6, 0xD7, 0x88, 0x02 },
	/* x */
	20,
	{ 0x20, 0x70, 0xB3, 0x22, 0x3D, 0xBA, 0x37, 0x2F,
	  0xDE, 0x1C, 0x0F, 0xFC, 0x7B, 0x2E, 0x3B, 0x49,
	  0x8B, 0x26, 0x06, 0x14 },
	/* y */
	64,
	{ 0x19, 0x13, 0x18, 0x71, 0xD7, 0x5B, 0x16, 0x12,
	  0xA8, 0x19, 0xF2, 0x9D, 0x78, 0xD1, 0xB0, 0xD7,
	  0x34, 0x6F, 0x7A, 0xA7, 0x7B, 0xB6, 0x2A, 0x85,
	  0x9B, 0xFD, 0x6C, 0x56, 0x75, 0xDA, 0x9D, 0x21,
	  0x2D, 0x3A, 0x36, 0xEF, 0x16, 0x72, 0xEF, 0x66,
	  0x0B, 0x8C, 0x7C, 0x25, 0x5C, 0xC0, 0xEC, 0x74,
	  0x85, 0x8F, 0xBA, 0x33, 0xF4, 0x4C, 0x06, 0x69,
	  0x96, 0x30, 0xA7, 0x6B, 0x03, 0x0E, 0xE3, 0x33 }
	};

int dhSelfTest( void )
	{
	void initKeyReadWrite( CONTEXT_INFO *contextInfoPtrPtr );
	CONTEXT_INFO contextInfoPtr1, contextInfoPtr2;
	PKC_INFO pkcInfoStorage1, pkcInfoStorage2, *pkcInfo;
	static const FAR_BSS CAPABILITY_INFO capabilityInfo = \
		{ CRYPT_ALGO_DH, 0, NULL, 64, 128, 512, 0 };
	KEYAGREE_PARAMS keyAgreeParams1, keyAgreeParams2;
	int status = CRYPT_OK;

	/* Initialise the key components */
	memset( &contextInfoPtr1, 0, sizeof( CONTEXT_INFO ) );
	memset( &pkcInfoStorage1, 0, sizeof( PKC_INFO ) );
	contextInfoPtr1.ctxPKC = pkcInfo = &pkcInfoStorage1;
	BN_init( &pkcInfo->dlpParam_p );
	BN_init( &pkcInfo->dlpParam_g );
	BN_init( &pkcInfo->dlpParam_q );
	BN_init( &pkcInfo->dlpParam_y );
	BN_init( &pkcInfo->dlpParam_x );
	BN_init( &pkcInfo->dhParam_yPrime );
	BN_init( &pkcInfo->tmp1 );
	BN_init( &pkcInfo->tmp2 );
	BN_init( &pkcInfo->tmp3 );
	BN_CTX_init( &pkcInfo->bnCTX );
	BN_MONT_CTX_init( &pkcInfo->rsaParam_mont_p );
	contextInfoPtr1.capabilityInfo = &capabilityInfo;
	initKeyReadWrite( &contextInfoPtr1 );
	BN_bin2bn( dlpTestKey.p, dlpTestKey.pLen, &pkcInfo->dlpParam_p );
	BN_bin2bn( dlpTestKey.g, dlpTestKey.gLen, &pkcInfo->dlpParam_g );
	BN_bin2bn( dlpTestKey.q, dlpTestKey.qLen, &pkcInfo->dlpParam_q );
	BN_bin2bn( dlpTestKey.y, dlpTestKey.yLen, &pkcInfo->dlpParam_y );
	BN_bin2bn( dlpTestKey.x, dlpTestKey.xLen, &pkcInfo->dlpParam_x );
	memset( &contextInfoPtr2, 0, sizeof( CONTEXT_INFO ) );
	memset( &pkcInfoStorage2, 0, sizeof( PKC_INFO ) );
	contextInfoPtr2.ctxPKC = pkcInfo = &pkcInfoStorage2;
	BN_init( &pkcInfo->dlpParam_p );
	BN_init( &pkcInfo->dlpParam_g );
	BN_init( &pkcInfo->dlpParam_q );
	BN_init( &pkcInfo->dlpParam_y );
	BN_init( &pkcInfo->dlpParam_x );
	BN_init( &pkcInfo->dhParam_yPrime );
	BN_init( &pkcInfo->tmp1 );
	BN_init( &pkcInfo->tmp2 );
	BN_init( &pkcInfo->tmp3 );
	BN_CTX_init( &pkcInfo->bnCTX );
	BN_MONT_CTX_init( &pkcInfo->rsaParam_mont_p );
	contextInfoPtr2.capabilityInfo = &capabilityInfo;
	initKeyReadWrite( &contextInfoPtr2 );
	BN_bin2bn( dlpTestKey.p, dlpTestKey.pLen, &pkcInfo->dlpParam_p );
	BN_bin2bn( dlpTestKey.g, dlpTestKey.gLen, &pkcInfo->dlpParam_g );
	BN_bin2bn( dlpTestKey.q, dlpTestKey.qLen, &pkcInfo->dlpParam_q );
	BN_bin2bn( dlpTestKey.y, dlpTestKey.yLen, &pkcInfo->dlpParam_y );
	BN_bin2bn( dlpTestKey.x, dlpTestKey.xLen, &pkcInfo->dlpParam_x );

	/* Perform the test key exchange on a block of data */
	memset( &keyAgreeParams1, 0, sizeof( KEYAGREE_PARAMS ) );
	memset( &keyAgreeParams2, 0, sizeof( KEYAGREE_PARAMS ) );
	status = dhInitKey( &contextInfoPtr1, NULL, 0 );
	if( cryptStatusOK( status ) )
		status = dhInitKey( &contextInfoPtr2, NULL, 0 );
	if( cryptStatusOK( status ) )
		status = dhEncrypt( &contextInfoPtr1, ( BYTE * ) &keyAgreeParams1,
							CRYPT_USE_DEFAULT );
	if( cryptStatusOK( status ) )
		status = dhEncrypt( &contextInfoPtr2, ( BYTE * ) &keyAgreeParams2,
							CRYPT_USE_DEFAULT );
	if( cryptStatusOK( status ) )
		status = dhDecrypt( &contextInfoPtr1, ( BYTE * ) &keyAgreeParams2,
							CRYPT_USE_DEFAULT );
	if( cryptStatusOK( status ) )
		status = dhDecrypt( &contextInfoPtr2, ( BYTE * ) &keyAgreeParams1,
							CRYPT_USE_DEFAULT );
	if( cryptStatusError( status ) || \
		memcmp( keyAgreeParams1.wrappedKey, keyAgreeParams2.wrappedKey, 64 ) )
		status = CRYPT_ERROR;

	/* Clean up */
	pkcInfo = contextInfoPtr1.ctxPKC;
	BN_clear_free( &pkcInfo->dlpParam_p );
	BN_clear_free( &pkcInfo->dlpParam_g );
	BN_clear_free( &pkcInfo->dlpParam_q );
	BN_clear_free( &pkcInfo->dlpParam_y );
	BN_clear_free( &pkcInfo->dlpParam_x );
	BN_clear_free( &pkcInfo->dhParam_yPrime );
	BN_clear_free( &pkcInfo->tmp1 );
	BN_clear_free( &pkcInfo->tmp2 );
	BN_clear_free( &pkcInfo->tmp3 );
	BN_CTX_free( &pkcInfo->bnCTX );
	BN_MONT_CTX_free( &pkcInfo->dlpParam_mont_p );
	zeroise( &pkcInfoStorage1, sizeof( PKC_INFO ) );
	zeroise( &contextInfoPtr1, sizeof( CONTEXT_INFO ) );
	pkcInfo = contextInfoPtr2.ctxPKC;
	BN_clear_free( &pkcInfo->dlpParam_p );
	BN_clear_free( &pkcInfo->dlpParam_g );
	BN_clear_free( &pkcInfo->dlpParam_q );
	BN_clear_free( &pkcInfo->dlpParam_y );
	BN_clear_free( &pkcInfo->dlpParam_x );
	BN_clear_free( &pkcInfo->dhParam_yPrime );
	BN_clear_free( &pkcInfo->tmp1 );
	BN_clear_free( &pkcInfo->tmp2 );
	BN_clear_free( &pkcInfo->tmp3 );
	BN_CTX_free( &pkcInfo->bnCTX );
	BN_MONT_CTX_free( &pkcInfo->dlpParam_mont_p );
	zeroise( &pkcInfoStorage2, sizeof( PKC_INFO ) );
	zeroise( &contextInfoPtr2, sizeof( CONTEXT_INFO ) );

	return( status );
	}

/****************************************************************************
*																			*
*						Diffie-Hellman Key Exchange Routines				*
*																			*
****************************************************************************/

/* Perform phase 1 of Diffie-Hellman ("export") */

int dhEncrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	KEYAGREE_PARAMS *keyAgreeParams = ( KEYAGREE_PARAMS * ) buffer;

	UNUSED( noBytes );

	assert( !BN_is_zero( &pkcInfo->dlpParam_y ) );

	/* y is generated either at keygen time for static DH or as a side-effect
	   of the implicit generation of the x value for ephemeral DH, so all we
	   have to do is copy it to the output */
	keyAgreeParams->publicValueLen = \
							BN_bn2bin( &pkcInfo->dlpParam_y,
									   keyAgreeParams->publicValue );
	return( CRYPT_OK );

#if 0
	BN_CTX *bnCTX;

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Export y = g^x mod p.  There is no input data since x was set when the
	   DH values were loaded */
	BN_mod_exp_mont( &pkcInfo->dlpParam_y, &pkcInfo->dlpParam_g,
					 &pkcInfo->dlpParam_x, &pkcInfo->dlpParam_p, bnCTX,
					 &pkcInfo->dlpParam_mont_p );
	keyAgreeParams->publicValueLen = \
							BN_bn2bin( &pkcInfo->dlpParam_y,
									   keyAgreeParams->publicValue );
	BN_CTX_free( bnCTX );

	return( ( status == -1 ) ? CRYPT_ERROR_FAILED : status );
#endif /* 0 */
	}

/* Perform phase 2 of Diffie-Hellman ("import") */

int dhDecrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	KEYAGREE_PARAMS *keyAgreeParams = ( KEYAGREE_PARAMS * ) buffer;
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BIGNUM *z = &pkcInfo->tmp1;
	const int length = bitsToBytes( pkcInfo->keySizeBits );
	int i, bnStatus = BN_STATUS;

	/* Make sure we're not being fed suspiciously short data quantities */
	for( i = 0; i < length; i++ )
		if( keyAgreeParams->publicValue[ i ] )
			break;
	if( length - i < 56 )
		return( CRYPT_ERROR_BADDATA );

	/* The other party's y value will be stored with the key agreement info
	   rather than having been read in when we read the DH public key */
	BN_bin2bn( keyAgreeParams->publicValue, keyAgreeParams->publicValueLen,
			   &pkcInfo->dhParam_yPrime );

	/* Export z = y^x mod p.  We need to use separate y and z values because
	   the bignum code can't handle modexp with the first two parameters the
	   same */
	CK( BN_mod_exp_mont( z, &pkcInfo->dhParam_yPrime, &pkcInfo->dlpParam_x, 
						 &pkcInfo->dlpParam_p, &pkcInfo->bnCTX, 
						 &pkcInfo->dlpParam_mont_p ) );
	keyAgreeParams->wrappedKeyLen = BN_bn2bin( z, keyAgreeParams->wrappedKey );

	return( getBnStatus( bnStatus ) );
	}

/****************************************************************************
*																			*
*								Key Management								*
*																			*
****************************************************************************/

/* Load key components into an encryption context */

int dhInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	int status;

#ifndef USE_FIPS140
	/* Load the key component from the external representation into the
	   internal bignums unless we're doing an internal load */
	if( key != NULL )
		{
		const CRYPT_PKCINFO_DLP *dhKey = ( CRYPT_PKCINFO_DLP * ) key;

		contextInfoPtr->flags |= ( dhKey->isPublicKey ) ? \
							CONTEXT_ISPUBLICKEY : CONTEXT_ISPRIVATEKEY;
		BN_bin2bn( dhKey->p, bitsToBytes( dhKey->pLen ),
				   &pkcInfo->dlpParam_p );
		BN_bin2bn( dhKey->g, bitsToBytes( dhKey->gLen ),
				   &pkcInfo->dlpParam_g );
		BN_bin2bn( dhKey->q, bitsToBytes( dhKey->qLen ),
				   &pkcInfo->dlpParam_q );
		BN_bin2bn( dhKey->y, bitsToBytes( dhKey->yLen ),
				   &pkcInfo->dlpParam_y );
		if( !dhKey->isPublicKey )
			BN_bin2bn( dhKey->x, bitsToBytes( dhKey->xLen ),
					   &pkcInfo->dlpParam_x );
		contextInfoPtr->flags |= CONTEXT_PBO;
		}
#endif /* USE_FIPS140 */

	/* Complete the key checking and setup */
	status = initDLPkey( contextInfoPtr, TRUE );
	if( cryptStatusOK( status ) )
		/* DH keys may follow PKCS #3 rather than X9.42, which means we can't 
		   do extended checking using q, so if q is zero we denote it as a 
		   PKCS #3 key.  This is only permitted for DH keys, other key types
		   will fail the check if q = 0 */
		status = checkDLPkey( contextInfoPtr, 
							  BN_is_zero( &pkcInfo->dlpParam_q ) ? \
								TRUE : FALSE );
	if( cryptStatusOK( status ) )
		status = calculateKeyID( contextInfoPtr );
	return( status );
	}

/* Generate a key into an encryption context */

int dhGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits )
	{
	int status;

	status = generateDLPkey( contextInfoPtr, keySizeBits, CRYPT_USE_DEFAULT, 
							 TRUE );
	if( cryptStatusOK( status ) )
		status = calculateKeyID( contextInfoPtr );
	return( status );
	}
