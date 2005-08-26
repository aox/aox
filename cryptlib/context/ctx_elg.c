/****************************************************************************
*																			*
*					  cryptlib Elgamal Encryption Routines					*
*						Copyright Peter Gutmann 1997-2005					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
#else
  #include "crypt.h"
  #include "context/context.h"
#endif /* Compiler-specific includes */

#ifdef USE_ELGAMAL

/****************************************************************************
*																			*
*								Algorithm Self-test							*
*																			*
****************************************************************************/

/* Test the Elgamal implementation using the sample key from FIPS 186.
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

/* If we're doing a self-test we use the following fixed k (for the
   signature) and kRandom (for the encryption) data rather than a randomly-
   generated value.  The k value is the DSA one from FIPS 186, which seems as
   good as any */

#if 0	/* Only needed for Elgamal signing */

static const FAR_BSS BYTE kVal[] = {
	0x35, 0x8D, 0xAD, 0x57, 0x14, 0x62, 0x71, 0x0F,
	0x50, 0xE2, 0x54, 0xCF, 0x1A, 0x37, 0x6B, 0x2B,
	0xDE, 0xAA, 0xDF, 0xBF
	};
#endif /* 0 */

static const FAR_BSS BYTE kRandomVal[] = {
	0x2A, 0x7C, 0x01, 0xFD, 0x62, 0xF7, 0x43, 0x13,
	0x36, 0xFE, 0xE8, 0xF1, 0x68, 0xB2, 0xA2, 0x2F,
	0x76, 0x50, 0xA1, 0x2C, 0x3E, 0x64, 0x8E, 0xFE,
	0x04, 0x58, 0x7F, 0xDE, 0xC2, 0x34, 0xE5, 0x79,
	0xE9, 0x45, 0xB0, 0xDD, 0x5E, 0x56, 0xD7, 0x82,
	0xEF, 0x93, 0xEF, 0x5F, 0xD0, 0x71, 0x8B, 0xA1,
	0x3E, 0xA0, 0x55, 0x6A, 0xB9, 0x6E, 0x72, 0xFE,
	0x17, 0x03, 0x95, 0x50, 0xB7, 0xA1, 0x11, 0xBA,
	};

static BOOLEAN pairwiseConsistencyTest( CONTEXT_INFO *contextInfoPtr,
										const BOOLEAN isGeneratedKey )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = getElgamalCapability();
	DLP_PARAMS dlpParams;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 2 ) + 32 + 8 ];
	int encrSize, status;

	/* Encrypt with the public key */
	memset( buffer, 0, CRYPT_MAX_PKCSIZE );
	memcpy( buffer + 1, "abcde", 5 );
	setDLPParams( &dlpParams, buffer, 
				  bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits ),
				  buffer, ( CRYPT_MAX_PKCSIZE * 2 ) + 32 );
	if( !isGeneratedKey )
		/* Force the use of a fixed k value for the encryption test to
		   avoid having to go via the RNG */
		dlpParams.inLen2 = -999;
	status = capabilityInfoPtr->encryptFunction( contextInfoPtr, 
						( BYTE * ) &dlpParams, sizeof( DLP_PARAMS ) );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Decrypt with the private key */
	encrSize = dlpParams.outLen;
	setDLPParams( &dlpParams, buffer, encrSize, 
				  buffer, ( CRYPT_MAX_PKCSIZE * 2 ) + 32 );
	status = capabilityInfoPtr->decryptFunction( contextInfoPtr, 
						( BYTE * ) &dlpParams, sizeof( DLP_PARAMS ) );
	if( cryptStatusError( status ) )
		return( FALSE );
	return( !memcmp( buffer + 1, "abcde", 5 ) );
	}

static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = getElgamalCapability();
	CONTEXT_INFO contextInfoPtr;
	PKC_INFO pkcInfoStorage, *pkcInfo;
	int status;

	/* Initialise the key components */
	memset( &contextInfoPtr, 0, sizeof( CONTEXT_INFO ) );
	memset( &pkcInfoStorage, 0, sizeof( PKC_INFO ) );
	contextInfoPtr.ctxPKC = pkcInfo = &pkcInfoStorage;
	BN_init( &pkcInfo->dlpParam_p );
	BN_init( &pkcInfo->dlpParam_g );
	BN_init( &pkcInfo->dlpParam_q );
	BN_init( &pkcInfo->dlpParam_y );
	BN_init( &pkcInfo->dlpParam_x );
	BN_init( &pkcInfo->tmp1 );
	BN_init( &pkcInfo->tmp2 );
	BN_init( &pkcInfo->tmp3 );
	BN_init( &pkcInfo->dlpTmp1 );
	BN_init( &pkcInfo->dlpTmp2 );
	BN_CTX_init( &pkcInfo->bnCTX );
	BN_MONT_CTX_init( &pkcInfo->rsaParam_mont_p );
	contextInfoPtr.capabilityInfo = capabilityInfoPtr;
	initKeyWrite( &contextInfoPtr );	/* For calcKeyID() */
	BN_bin2bn( dlpTestKey.p, dlpTestKey.pLen, &pkcInfo->dlpParam_p );
	BN_bin2bn( dlpTestKey.g, dlpTestKey.gLen, &pkcInfo->dlpParam_g );
	BN_bin2bn( dlpTestKey.q, dlpTestKey.qLen, &pkcInfo->dlpParam_q );
	BN_bin2bn( dlpTestKey.y, dlpTestKey.yLen, &pkcInfo->dlpParam_y );
	BN_bin2bn( dlpTestKey.x, dlpTestKey.xLen, &pkcInfo->dlpParam_x );

	/* Perform a test a sig generation/check and test en/decryption */
#if 0	/* See comment in sig.code */
	memset( buffer, '*', 20 );
	status = capabilityInfoPtr->signFunction( &contextInfoPtr, buffer, -1 );
	if( !cryptStatusError( status ) )
		{
		memmove( buffer + 20, buffer, status );
		memset( buffer, '*', 20 );
		status = capabilityInfoPtr->sigCheckFunction( &contextInfoPtr, 
													  buffer, 20 + status );
		}
	if( status != CRYPT_OK )
		status = CRYPT_ERROR;
#endif /* 0 */
	status = capabilityInfoPtr->initKeyFunction( &contextInfoPtr, NULL, 0 );
	if( cryptStatusOK( status ) && \
		!pairwiseConsistencyTest( &contextInfoPtr, FALSE ) )
		status = CRYPT_ERROR;

	/* Clean up */
	BN_clear_free( &pkcInfo->dlpParam_p );
	BN_clear_free( &pkcInfo->dlpParam_g );
	BN_clear_free( &pkcInfo->dlpParam_q );
	BN_clear_free( &pkcInfo->dlpParam_y );
	BN_clear_free( &pkcInfo->dlpParam_x );
	BN_clear_free( &pkcInfo->tmp1 );
	BN_clear_free( &pkcInfo->tmp2 );
	BN_clear_free( &pkcInfo->tmp3 );
	BN_clear_free( &pkcInfo->dlpTmp1 );
	BN_clear_free( &pkcInfo->dlpTmp2 );
	BN_CTX_free( &pkcInfo->bnCTX );
	BN_MONT_CTX_free( &pkcInfo->dlpParam_mont_p );
	zeroise( &pkcInfoStorage, sizeof( PKC_INFO ) );
	zeroise( &contextInfoPtr, sizeof( CONTEXT_INFO ) );

	return( status );
	}

/****************************************************************************
*																			*
*							Create/Check a Signature						*
*																			*
****************************************************************************/

/* Elgamal signatures have potential security problems (although this isn't
   an issue when they're used in a PKCS #1 manner, OTOH nothing apart from
   cryptlib uses them like this) while the equivalent DSA signatures don't
   (or at least have less than Elgamal).  In addition since nothing uses
   them anyway this code, while fully functional, is disabled (there's no
   benefit to having it present and active) */

#if 0

/* Since Elgamal signature generation produces two values and the
   cryptEncrypt() model only provides for passing a byte string in and out
   (or, more specifically, the internal bignum data can't be exported to the
   outside world), we need to encode the resulting data into a flat format.
   This is done by encoding the output as an Elgamal-Sig record:

	Elgamal-Sig ::= SEQUENCE {
		r	INTEGER,
		s	INTEGER
		}

   The input is the 160-bit hash, usually SHA but possibly also RIPEMD-160 */

/* The size of the Elgamal signature hash component is 160 bits */

#define ELGAMAL_SIGPART_SIZE	20

/* Sign a single block of data  */

static int sign( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = &contextInfoPtr->ctxPKC;
	BIGNUM *p = &pkcInfo->dlpParam_p, *g = &pkcInfo->dlpParam_g;
	BIGNUM *x = &pkcInfo->dlpParam_x;
	BIGNUM *tmp = &pkcInfo->tmp1, *k = &pkcInfo->tmp2, *kInv = &pkcInfo->tmp3;
	BIGNUM *r = &pkcInfo->dlpTmp1, *s = &pkcInfo->dlpTmp2;
	BIGNUM *phi_p = &pkcInfo->dlpTmp3;
	BYTE *bufPtr = buffer;
	int length, status = CRYPT_OK;

	assert( noBytes == ELGAMAL_SIGPART_SIZE || noBytes == -1 );

	/* Generate the secret random value k.  During the initial self-test
	   the random data pool may not exist yet, and may in fact never exist in
	   a satisfactory condition if there isn't enough randomness present in
	   the system to generate cryptographically strong random numbers.  To
	   bypass this problem, if the caller passes in a noBytes value that
	   can't be passed in via a call to cryptEncrypt() we know it's an
	   internal self-test call and use a fixed bit pattern for k that avoids
	   having to call generateBignum().  This is a somewhat ugly use of
	   'magic numbers', but it's safe because cryptEncrypt() won't allow any
	   such value for noBytes so there's no way an external caller can pass
	   in a value like this */
	if( noBytes == -1 )
		BN_bin2bn( ( BYTE * ) kVal, ELGAMAL_SIGPART_SIZE, k );
	else
		{
		status = generateBignum( k, bytesToBits( ELGAMAL_SIGPART_SIZE ) + 32,
								 0x80, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Generate phi( p ) and use it to get k, k < p-1 and k relatively prime
	   to p-1.  Since (p-1)/2 is prime, the initial choice for k will be
	   divisible by (p-1)/2 with probability 2/(p-1), so we'll do at most two
	   gcd operations with very high probability.  A k of (p-3)/2 will be
	   chosen with probability 3/(p-1), and all other numbers from 1 to p-1
	   will be chosen with probability 2/(p-1), giving a nearly uniform
	   distribution of exponents */
	BN_copy( phi_p, p );
	BN_sub_word( phi_p, 1 );			/* phi( p ) = p - 1 */
	BN_mod( k, k, phi_p,				/* Reduce k to the correct range */
			&pkcInfo->bnCTX );
	BN_gcd( r, k, phi_p, &pkcInfo->bnCTX );
	while( !BN_is_one( r ) )
		{
		BN_sub_word( k, 1 );
		BN_gcd( r, k, phi_p, &pkcInfo->bnCTX );
		}

	/* Move the data from the buffer into a bignum */
	BN_bin2bn( bufPtr, ELGAMAL_SIGPART_SIZE, s );

	/* r = g^k mod p */
	BN_mod_exp_mont( r, g, k, p, &pkcInfo->bnCTX, &pkcInfo->dlpParam_mont_p );	
										/* r = g^k mod p */

	/* s = ( k^-1 * ( hash - x * r ) ) mod phi( p ) */
	kInv = BN_mod_inverse( k, phi_p,	/* k = ( k^-1 ) mod phi( p ) */
						   &pkcInfo->bnCTX );
	BN_mod_mul( tmp, x, r, phi_p,		/* tmp = ( x * r ) mod phi( p ) */
				&pkcInfo->bnCTX );
	if( BN_cmp( s, tmp ) < 0 )			/* if hash < x * r */
		BN_add( s, s, phi_p );			/*   hash = hash + phi( p ) (fast mod) */
	BN_sub( s, s, tmp );				/* s = hash - x * r */
	BN_mod_mul( s, s, kInv, phi_p,		/* s = ( s * k^-1 ) mod phi( p ) */ 
				&pkcInfo->bnCTX );

	/* Encode the result as a DL data block */
	length = encodeDLValues( buffer, r, s );

	return( ( status == -1 ) ? CRYPT_ERROR_FAILED : length );
	}

/* Signature check a single block of data */

static int sigCheck( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = &contextInfoPtr->ctxPKC;
	BIGNUM *p = &pkcInfo->dlpParam_p, *g = &pkcInfo->dlpParam_g;
	BIGNUM *y = &pkcInfo->dlpParam_y;
	BIGNUM *r = &pkcInfo->tmp1, *s = &pkcInfo->tmp1;
	int	status;

	/* Decode the values from a DL data block and make sure that r and s are
	   valid */
	status = decodeDLValues( buffer + ELGAMAL_SIGPART_SIZE, noBytes, &r, &s );
	if( cryptStatusError( status ) )
		return( status );

	/* Verify that 0 < r < p.  If this check isn't done, an adversary can
	   forge signatures given one existing valid signature for a key */
	if( BN_is_zero( r ) || BN_cmp( r, p ) >= 0 )
		status = CRYPT_ERROR_SIGNATURE;
	else
		{
		BIGNUM *hash, *u1, *u2;

		hash = BN_new();
		u1 = BN_new();
		u2 = BN_new();

		BN_bin2bn( buffer, ELGAMAL_SIGPART_SIZE, hash );

		/* u1 = ( y^r * r^s ) mod p */
		BN_mod_exp_mont( u1, y, r, p,		/* y' = ( y^r ) mod p */
						 &pkcInfo->bnCTX, &pkcInfo->dlpParam_mont_p );	
		BN_mod_exp_mont( r, r, s, p, 		/* r' = ( r^s ) mod p */
						 &pkcInfo->bnCTX, &pkcInfo->dlpParam_mont_p );	
		BN_mod_mul_mont( u1, u1, r, p,		/* u1 = ( y' * r' ) mod p */
						 &pkcInfo->bnCTX, &pkcInfo->dlpParam_mont_p );	

		/* u2 = g^hash mod p */
		BN_mod_exp_mont( u2, g, hash, p, &pkcInfo->bnCTX,
						 &pkcInfo->dlpParam_mont_p );

		/* if u1 == u2, signature is good */
		if( BN_cmp( u1, u2 ) && cryptStatusOK( status ) )
			status = CRYPT_ERROR_SIGNATURE;

		BN_clear_free( hash );
		BN_clear_free( u2 );
		BN_clear_free( u1 );
		}

	return( status );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*						Encrypt/Decrypt a Data Block						*
*																			*
****************************************************************************/

/* Encrypt a single block of data.  We have to append the distinguisher 'Fn' 
   to the name since some systems already have 'encrypt' and 'decrypt' in 
   their standard headers */

static int encryptFn( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) buffer;
	BIGNUM *p = &pkcInfo->dlpParam_p, *g = &pkcInfo->dlpParam_g;
	BIGNUM *y = &pkcInfo->dlpParam_y;
	BIGNUM *tmp = &pkcInfo->tmp1, *k = &pkcInfo->tmp2;
	BIGNUM *r = &pkcInfo->tmp3, *s = &pkcInfo->dlpTmp1;
	BIGNUM *phi_p = &pkcInfo->dlpTmp2;
	const int length = bitsToBytes( pkcInfo->keySizeBits );
	int i, bnStatus = BN_STATUS, status;

	assert( noBytes == sizeof( DLP_PARAMS ) );
	assert( dlpParams->inParam1 != NULL && dlpParams->inLen1 == length );
	assert( dlpParams->inParam2 == NULL && \
			( dlpParams->inLen2 == 0 || dlpParams->inLen2 == -999 ) );
	assert( dlpParams->outParam != NULL && \
			dlpParams->outLen >= ( 2 + length ) * 2 );

	/* Make sure that we're not being fed suspiciously short data 
	   quantities */
	for( i = 0; i < length; i++ )
		if( buffer[ i ] )
			break;
	if( length - i < 56 )
		return( CRYPT_ERROR_BADDATA );

	/* Generate the secret random value k.  During the initial self-test
	   the random data pool may not exist yet, and may in fact never exist in
	   a satisfactory condition if there isn't enough randomness present in
	   the system to generate cryptographically strong random numbers.  To
	   bypass this problem, if the caller passes in a second length parameter 
	   of -999, we know that it's an internal self-test call and use a fixed 
	   bit pattern for k that avoids having to call generateBignum().  This 
	   is a somewhat ugly use of 'magic numbers', but it's safe because this 
	   function can only be called internally, so all we need to trap is 
	   accidental use of the parameter which is normally unused */
	if( dlpParams->inLen2 == -999 )
		BN_bin2bn( ( BYTE * ) kRandomVal, length, k );
	else
		{
		/* Generate the random value k, with the same 32-bit adjustment used
		   in the DSA code to avoid bias in the output (the only real
		   difference is that we eventually reduce it mode phi(p) rather than 
		   mod q) */
		status = generateBignum( k, bytesToBits( length ) + 32, 0x80, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Generate phi( p ) and use it to get k, k < p-1 and k relatively prime
	   to p-1.  Since (p-1)/2 is prime, the initial choice for k will be
	   divisible by (p-1)/2 with probability 2/(p-1), so we'll do at most two
	   gcd operations with very high probability.  A k of (p-3)/2 will be
	   chosen with probability 3/(p-1), and all other numbers from 1 to p-1
	   will be chosen with probability 2/(p-1), giving a nearly uniform
	   distribution of exponents */
	CKPTR( BN_copy( phi_p, p ) );
	CK( BN_sub_word( phi_p, 1 ) );		/* phi( p ) = p - 1 */
	CK( BN_mod( k, k, phi_p,			/* Reduce k to the correct range */
				&pkcInfo->bnCTX ) );
	CK( BN_gcd( s, k, phi_p, &pkcInfo->bnCTX ) );
	while( bnStatusOK( bnStatus ) && !BN_is_one( s ) )
		{
		CK( BN_sub_word( k, 1 ) );
		CK( BN_gcd( s, k, phi_p, &pkcInfo->bnCTX ) );
		}
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Move the input data into a bignum */
	BN_bin2bn( ( BYTE * ) dlpParams->inParam1, length, tmp );

	/* s = ( y^k * M ) mod p */
	CK( BN_mod_exp_mont( r, y, k, p,	/* y' = y^k mod p */
						 &pkcInfo->bnCTX, &pkcInfo->dlpParam_mont_p ) );
	CK( BN_mod_mul( s, r, tmp, p,		/* s = y'M mod p */
					&pkcInfo->bnCTX ) );

	/* r = g^k mod p */
	CK( BN_mod_exp_mont( r, g, k, p, &pkcInfo->bnCTX,
						 &pkcInfo->dlpParam_mont_p ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Encode the result as a DL data block */
	status = encodeDLValues( dlpParams->outParam, dlpParams->outLen, r, s,
							 dlpParams->formatType );
	if( !cryptStatusError( status ) )
		{
		dlpParams->outLen = status;
		status = CRYPT_OK;	/* encodeDLValues() returns a byte count */
		}
	return( status );
	}

/* Decrypt a single block of data */

static int decryptFn( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) buffer;
	BIGNUM *p = &pkcInfo->dlpParam_p, *x = &pkcInfo->dlpParam_x;
	BIGNUM *r = &pkcInfo->tmp1, *s = &pkcInfo->tmp2, *tmp = &pkcInfo->tmp3;
	const int length = bitsToBytes( pkcInfo->keySizeBits );
	int bnStatus = BN_STATUS, status;

	assert( noBytes == sizeof( DLP_PARAMS ) );
	assert( dlpParams->inParam1 != NULL && \
			dlpParams->inLen1 >= ( 2 + ( length - 1 ) ) * 2 );
	assert( dlpParams->inParam2 == NULL && dlpParams->inLen2 == 0 );
	assert( dlpParams->outParam != NULL && dlpParams->outLen >= length );

	/* Decode the values from a DL data block and make sure that r and s are
	   valid */
	status = decodeDLValues( dlpParams->inParam1, dlpParams->inLen1, &r, &s,
							 dlpParams->formatType );
	if( cryptStatusError( status ) )
		return( status );
	if( BN_cmp( r, p ) >= 0 || BN_cmp( s, p ) >= 0 )
		return( CRYPT_ERROR_BADDATA );

	/* M = ( s / ( r^x ) ) mod p */
	CK( BN_mod_exp_mont( r, r, x, p,		/* r' = r^x */
						 &pkcInfo->bnCTX, &pkcInfo->dlpParam_mont_p ) );
	CKPTR( BN_mod_inverse( tmp, r, p,		/* r'' = r'^-1 */
						   &pkcInfo->bnCTX ) );
	CK( BN_mod_mul( s, s, tmp, p,			/* s = s * r'^-1 mod p */
					&pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Copy the result to the output.  Since the bignum code performs 
	   leading-zero truncation, we have to adjust where we copy the 
	   result to in the buffer to take into account extra zero bytes 
	   that aren't extracted from the bignum */
	memset( dlpParams->outParam, 0, 16 );
	BN_bn2bin( s, dlpParams->outParam + ( length - BN_num_bytes( s ) ) );
	dlpParams->outLen = length;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Key Management								*
*																			*
****************************************************************************/

/* Load key components into an encryption context */

static int initKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					const int keyLength )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	int status;

#ifndef USE_FIPS140
	/* Load the key component from the external representation into the
	   internal bignums unless we're doing an internal load */
	if( key != NULL )
		{
		const CRYPT_PKCINFO_DLP *egKey = ( CRYPT_PKCINFO_DLP * ) key;

		/* Load the key components into the bignums */
		contextInfoPtr->flags |= ( egKey->isPublicKey ) ? \
							CONTEXT_ISPUBLICKEY : CONTEXT_ISPRIVATEKEY;
		BN_bin2bn( egKey->p, bitsToBytes( egKey->pLen ),
				   &pkcInfo->dlpParam_p );
		BN_bin2bn( egKey->g, bitsToBytes( egKey->gLen ),
				   &pkcInfo->dlpParam_g );
		BN_bin2bn( egKey->q, bitsToBytes( egKey->qLen ),
				   &pkcInfo->dlpParam_q );
		BN_bin2bn( egKey->y, bitsToBytes( egKey->yLen ),
				   &pkcInfo->dlpParam_y );
		if( !egKey->isPublicKey )
			BN_bin2bn( egKey->x, bitsToBytes( egKey->xLen ),
					   &pkcInfo->dlpParam_x );
		contextInfoPtr->flags |= CONTEXT_PBO;
		}
#endif /* USE_FIPS140 */

	/* Complete the key checking and setup */
	status = initDLPkey( contextInfoPtr, FALSE );
	if( cryptStatusOK( status ) )
		/* PGP Elgamal keys don't follow X9.42 and are effectively PKCS #3 
		   keys, so if the key is being instantiated from PGP key data and 
		   doesn't have a q parameter, we mark it as a PKCS #3 key to 
		   ensure that it doesn't fail the validity check for q != 0 */
		status = checkDLPkey( contextInfoPtr, 
					( key == NULL && pkcInfo->openPgpKeyIDSet && \
					  BN_is_zero( &pkcInfo->dlpParam_q ) ) ? \
					TRUE : FALSE );
	if( cryptStatusOK( status ) )
		status = calculateKeyID( contextInfoPtr );
	return( status );
	}

/* Generate a key into an encryption context */

static int generateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits )
	{
	int status;

	status = generateDLPkey( contextInfoPtr, keySizeBits, CRYPT_USE_DEFAULT,
							 TRUE );
	if( cryptStatusOK( status ) && 
#ifndef USE_FIPS140
		( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION ) &&
#endif /* USE_FIPS140 */
		!pairwiseConsistencyTest( contextInfoPtr, TRUE ) )
		{
		assert( NOTREACHED );
		status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		status = calculateKeyID( contextInfoPtr );
	return( status );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO FAR_BSS capabilityInfo = {
	CRYPT_ALGO_ELGAMAL, bitsToBytes( 0 ), "Elgamal",
	bitsToBytes( MIN_PKCSIZE_BITS ), bitsToBytes( 1024 ), CRYPT_MAX_PKCSIZE,
	selfTest, getDefaultInfo, NULL, NULL, initKey, generateKey, encryptFn, decryptFn
	};

const CAPABILITY_INFO *getElgamalCapability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_ELGAMAL */
