/****************************************************************************
*																			*
*						cryptlib DSA Encryption Routines					*
*						Copyright Peter Gutmann 1995-2005					*
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

/****************************************************************************
*																			*
*						Predefined DSA p, q, and g Parameters				*
*																			*
****************************************************************************/

/* We never use shared DSA parameters because they allow forgery of
   signatures on certificates.  This works as follows: Suppose that the
   certificate contains a copy of the certificate signer's DSA parameters,
   and the verifier of the certificate has a copy of the signer's public key
   but not the signer's DSA parameters (which are shared with other keys).
   If the verifier uses the DSA parameters from the certificate along with
   the signer's public key to verify the signature on the certificate, then
   an attacker can create bogus certificates by choosing a random u and
   finding its inverse v modulo q (uv is congruent to 1 modulo q).  Then
   take the certificate signer's public key g^x and compute g' = (g^x)^u.
   Then g'^v = g^x.  Using the DSA parameters p, q, g', the signer's public
   key corresponds to the private key v, which the attacker knows.  The
   attacker can then create a bogus certificate, put parameters (p, q, g')
   in it, and sign it with the DSA private key v to create an apparently
   valid certificate.  This works with the DSA OID that makes p, q, and g
   unauthenticated public parameters and y the public key, but not the one
   that makes p, q, g, and y the public key */

/****************************************************************************
*																			*
*								Algorithm Self-test							*
*																			*
****************************************************************************/

/* Test the DSA implementation using the sample key and hash from FIPS 186.
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

static const FAR_BSS BYTE shaM[] = {
	0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
	0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
	0x9C, 0xD0, 0xD8, 0x9D
	};

/* If we're doing a self-test using the FIPS 186 values we use the following
   fixed k data rather than a randomly-generated value */

static const FAR_BSS BYTE kVal[] = {
	0x35, 0x8D, 0xAD, 0x57, 0x14, 0x62, 0x71, 0x0F,
	0x50, 0xE2, 0x54, 0xCF, 0x1A, 0x37, 0x6B, 0x2B,
	0xDE, 0xAA, 0xDF, 0xBF
	};

static BOOLEAN pairwiseConsistencyTest( CONTEXT_INFO *contextInfoPtr )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = getDSACapability();
	DLP_PARAMS dlpParams;
	BYTE buffer[ 128 ];
	int sigSize, status;

	/* Generate a signature with the private key */
	setDLPParams( &dlpParams, shaM, 20, buffer, 128 );
	dlpParams.inLen2 = -999;
	status = capabilityInfoPtr->signFunction( contextInfoPtr, 
						( BYTE * ) &dlpParams, sizeof( DLP_PARAMS ) );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Verify the signature with the public key */
	sigSize = dlpParams.outLen;
	setDLPParams( &dlpParams, shaM, 20, NULL, 0 );
	dlpParams.inParam2 = buffer;
	dlpParams.inLen2 = sigSize;
	status = capabilityInfoPtr->sigCheckFunction( contextInfoPtr, 
						( BYTE * ) &dlpParams, sizeof( DLP_PARAMS ) );
	return( cryptStatusOK( status ) ? TRUE : FALSE );
	}

static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = getDSACapability();
	CONTEXT_INFO contextInfoPtr;
	PKC_INFO pkcInfoStorage, *pkcInfo;
	int status;

	/* Initialise the key components */
	memset( &contextInfoPtr, 0, sizeof( CONTEXT_INFO ) );
	memset( &pkcInfoStorage, 0, sizeof( PKC_INFO ) );
	contextInfoPtr.ctxPKC = pkcInfo = &pkcInfoStorage;
	BN_init( &pkcInfo->dlpParam_p );
	BN_init( &pkcInfo->dlpParam_q );
	BN_init( &pkcInfo->dlpParam_g );
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
	BN_bin2bn( dlpTestKey.q, dlpTestKey.qLen, &pkcInfo->dlpParam_q );
	BN_bin2bn( dlpTestKey.g, dlpTestKey.gLen, &pkcInfo->dlpParam_g );
	BN_bin2bn( dlpTestKey.y, dlpTestKey.yLen, &pkcInfo->dlpParam_y );
	BN_bin2bn( dlpTestKey.x, dlpTestKey.xLen, &pkcInfo->dlpParam_x );

	/* Perform the test sign/sig.check of the FIPS 186 test values */
	status = capabilityInfoPtr->initKeyFunction( &contextInfoPtr, NULL, 0 );
	if( cryptStatusOK( status ) && \
		!pairwiseConsistencyTest( &contextInfoPtr ) )
		status = CRYPT_ERROR;

	/* Clean up */
	BN_clear_free( &pkcInfo->dlpParam_p );
	BN_clear_free( &pkcInfo->dlpParam_q );
	BN_clear_free( &pkcInfo->dlpParam_g );
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

/* Since DSA signature generation produces two values and the cryptEncrypt()
   model only provides for passing a byte string in and out (or, more
   specifically, the internal bignum data can't be exported to the outside
   world), we need to encode the resulting data into a flat format.  This is
   done by encoding the output as an X9.31 Dss-Sig record:

	Dss-Sig ::= SEQUENCE {
		r	INTEGER,
		s	INTEGER
		}

   The input is the 160-bit hash, usually SHA but possibly also RIPEMD-160 */

/* The size of each DSA signature component - 160 bits */

#define DSA_SIGPART_SIZE	20

/* Sign a single block of data  */

static int sign( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) buffer;
	BIGNUM *p = &pkcInfo->dlpParam_p, *q = &pkcInfo->dlpParam_q;
	BIGNUM *g = &pkcInfo->dlpParam_g, *x = &pkcInfo->dlpParam_x;
	BIGNUM *hash = &pkcInfo->tmp1, *k = &pkcInfo->tmp2, *kInv = &pkcInfo->tmp3;
	BIGNUM *r = &pkcInfo->dlpTmp1, *s = &pkcInfo->dlpTmp2;
	int bnStatus = BN_STATUS, status;

	assert( noBytes == sizeof( DLP_PARAMS ) );
	assert( dlpParams->inParam1 != NULL && \
			dlpParams->inLen1 == DSA_SIGPART_SIZE );
	assert( dlpParams->inParam2 == NULL && \
			( dlpParams->inLen2 == 0 || dlpParams->inLen2 == -999 ) );
	assert( dlpParams->outParam != NULL && \
			dlpParams->outLen >= ( 2 + DSA_SIGPART_SIZE ) * 2 );

	/* Generate the secret random value k.  During the initial self-test
	   the random data pool may not exist yet, and may in fact never exist in
	   a satisfactory condition if there isn't enough randomness present in
	   the system to generate cryptographically strong random numbers.  To
	   bypass this problem, if the caller passes in a second length parameter 
	   of -999, we know that it's an internal self-test call and use a fixed 
	   bit pattern for k that avoids having to call generateBignum() (this 
	   also means we can use the FIPS 186 self-test value for k).  This is a 
	   somewhat ugly use of 'magic numbers', but it's safe because this 
	   function can only be called internally, so all we need to trap is 
	   accidental use of the parameter which is normally unused */
	if( dlpParams->inLen2 == -999 )
		BN_bin2bn( ( BYTE * ) kVal, DSA_SIGPART_SIZE, k );
	else
		{
		/* Generate the random value k.  FIPS 186 requires (Appendix 3)
		   that this be done with:

			k = G(t,KKEY) mod q

		   where G(t,c) produces a 160-bit output, however this produces a
		   slight bias in k that leaks a small amount of the private key in
		   each signature.  Because of this we start with a value which is
		   32 bits larger than q and then do the reduction, eliminating the
		   bias */
		status = generateBignum( k, bytesToBits( DSA_SIGPART_SIZE ) + 32,
								 0, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}
	CK( BN_mod( k, k, q, 				/* Reduce k to the correct range */
				&pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Move the data from the buffer into a bignum */
	BN_bin2bn( ( BYTE * ) dlpParams->inParam1, DSA_SIGPART_SIZE, hash );

	/* r = ( g ^ k mod p ) mod q */
	CK( BN_mod_exp_mont( r, g, k, p, &pkcInfo->bnCTX, 
						 &pkcInfo->dlpParam_mont_p ) );
	CK( BN_mod( r, r, q, &pkcInfo->bnCTX ) );

	/* s = k^-1 * ( hash + x * r ) mod q */
	CKPTR( BN_mod_inverse( kInv, k, q,	/* temp = k^-1 mod q */
						   &pkcInfo->bnCTX ) );
/*	BN_mul( s, x, r );					// s = x * r */
	CK( BN_mod_mul( s, x, r, q,			/* s = ( x * r ) mod q */
					&pkcInfo->bnCTX ) );
	CK( BN_add( s, s, hash ) );			/* s = s + hash */
	if( BN_cmp( s, q ) > 0 )			/* if s > q */
		CK( BN_sub( s, s, q ) );		/*   s = s - q (fast mod) */
	CK( BN_mod_mul( s, s, kInv, q,		/* s = k^-1 * ( hash + x * r ) mod q */
					&pkcInfo->bnCTX ) );
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

/* Signature check a single block of data */

static int sigCheck( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) buffer;
	BIGNUM *p = &pkcInfo->dlpParam_p, *q = &pkcInfo->dlpParam_q;
	BIGNUM *g = &pkcInfo->dlpParam_g, *y = &pkcInfo->dlpParam_y;
	BIGNUM *r = &pkcInfo->tmp1, *s = &pkcInfo->tmp2;
	BIGNUM *u1 = &pkcInfo->tmp3, *u2 = &pkcInfo->dlpTmp1;	/* Doubles as w */
	int bnStatus = BN_STATUS, status;

	assert( noBytes == sizeof( DLP_PARAMS ) );
	assert( dlpParams->inParam1 != NULL && dlpParams->inLen1 == 20 );
	assert( dlpParams->inParam2 != NULL && \
			( ( dlpParams->formatType == CRYPT_FORMAT_CRYPTLIB && \
				( dlpParams->inLen2 >= 42 && dlpParams->inLen2 <= 48 ) ) || \
			  ( dlpParams->formatType == CRYPT_FORMAT_PGP && \
				( dlpParams->inLen2 >= 42 && dlpParams->inLen2 <= 44 ) ) || \
			  ( dlpParams->formatType == CRYPT_IFORMAT_SSH && \
				dlpParams->inLen2 == 40 ) ) );
	assert( dlpParams->outParam == NULL && dlpParams->outLen == 0 );

	/* Decode the values from a DL data block and make sure that r and s are
	   valid */
	status = decodeDLValues( dlpParams->inParam2, dlpParams->inLen2, &r, &s,
							 dlpParams->formatType );
	if( cryptStatusError( status ) )
		return( status );
	if( BN_cmp( r, q ) >= 0 || BN_cmp( s, q ) >= 0 )
		return( CRYPT_ERROR_BADDATA );

	BN_bin2bn( ( BYTE * ) dlpParams->inParam1, DSA_SIGPART_SIZE, u1 );

	/* w = s^-1 mod q */
	CKPTR( BN_mod_inverse( u2, s, q,	/* w = s^-1 mod q */
						   &pkcInfo->bnCTX ) );

	/* u1 = ( hash * w ) mod q */
	CK( BN_mod_mul( u1, u1, u2, q,		/* u1 = ( hash * w ) mod q */
					&pkcInfo->bnCTX ) );

	/* u2 = ( r * w ) mod q */
	CK( BN_mod_mul( u2, r, u2, q,		/* u2 = ( r * w ) mod q */
					&pkcInfo->bnCTX ) );

	/* v = ( ( ( g^u1 ) * ( y^u2 ) ) mod p ) mod q */
	CK( BN_mod_exp2_mont( u2, g, u1, y, u2, p, &pkcInfo->bnCTX,
						  &pkcInfo->dlpParam_mont_p ) );
	CK( BN_mod( s, u2, q, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* if r == s signature is good */
	return( BN_cmp( r, s ) ? CRYPT_ERROR_SIGNATURE : CRYPT_OK );
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
	int status;

#ifndef USE_FIPS140
	/* Load the key component from the external representation into the
	   internal bignums unless we're doing an internal load */
	if( key != NULL )
		{
		PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
		const CRYPT_PKCINFO_DLP *dsaKey = ( CRYPT_PKCINFO_DLP * ) key;

		contextInfoPtr->flags |= ( dsaKey->isPublicKey ) ? \
							CONTEXT_ISPUBLICKEY : CONTEXT_ISPRIVATEKEY;
		BN_bin2bn( dsaKey->p, bitsToBytes( dsaKey->pLen ),
				   &pkcInfo->dlpParam_p );
		BN_bin2bn( dsaKey->q, bitsToBytes( dsaKey->qLen ),
				   &pkcInfo->dlpParam_q );
		BN_bin2bn( dsaKey->g, bitsToBytes( dsaKey->gLen ),
				   &pkcInfo->dlpParam_g );
		BN_bin2bn( dsaKey->y, bitsToBytes( dsaKey->yLen ),
				   &pkcInfo->dlpParam_y );
		if( !dsaKey->isPublicKey )
			BN_bin2bn( dsaKey->x, bitsToBytes( dsaKey->xLen ),
					   &pkcInfo->dlpParam_x );
		contextInfoPtr->flags |= CONTEXT_PBO;
		}
#endif /* USE_FIPS140 */

	/* Complete the key checking and setup */
	status = initDLPkey( contextInfoPtr, FALSE );
	if( cryptStatusOK( status ) )
		status = checkDLPkey( contextInfoPtr, FALSE );
	if( cryptStatusOK( status ) )
		status = calculateKeyID( contextInfoPtr );
	return( status );
	}

/* Generate a key into an encryption context */

static int generateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits )
	{
	int status;

	status = generateDLPkey( contextInfoPtr, ( keySizeBits / 64 ) * 64, 160,
							 TRUE );
	if( cryptStatusOK( status ) && 
#ifndef USE_FIPS140
		( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION ) &&
#endif /* USE_FIPS140 */
		!pairwiseConsistencyTest( contextInfoPtr ) )
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
	CRYPT_ALGO_DSA, bitsToBytes( 0 ), "DSA",
	bitsToBytes( MIN_PKCSIZE_BITS ), bitsToBytes( 1024 ), CRYPT_MAX_PKCSIZE,
	selfTest, getDefaultInfo, NULL, NULL, initKey, generateKey,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, sign, sigCheck
	};

const CAPABILITY_INFO *getDSACapability( void )
	{
	return( &capabilityInfo );
	}
