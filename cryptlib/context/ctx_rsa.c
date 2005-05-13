/****************************************************************************
*																			*
*						cryptlib RSA Encryption Routines					*
*						Copyright Peter Gutmann 1993-2004					*
*																			*
****************************************************************************/

/* I suppose if we all used pure RSA, the Illuminati would blackmail God into
   putting a trapdoor into the laws of mathematics.
														-- Lyle Seaman */
#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "libs.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
  #include "libs.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "context/libs.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Algorithm Self-test							*
*																			*
****************************************************************************/

/* Test the RSA implementation using a sample key.  Because a lot of the
   high-level encryption routines don't exist yet, we cheat a bit and set
   up a dummy encryption context with just enough information for the
   following code to work */

typedef struct {
	const int nLen; const BYTE n[ 64 ];
	const int eLen; const BYTE e[ 1 ];
	const int dLen; const BYTE d[ 64 ];
	const int pLen; const BYTE p[ 32 ];
	const int qLen; const BYTE q[ 32 ];
	const int uLen; const BYTE u[ 32 ];
	const int e1Len; const BYTE e1[ 32 ];
	const int e2Len; const BYTE e2[ 32 ];
	} RSA_PRIVKEY;

static const FAR_BSS RSA_PRIVKEY rsaTestKey = {
	/* n */
	64,
	{ 0xE1, 0x95, 0x41, 0x17, 0xB4, 0xCB, 0xDC, 0xD0,
	  0xCB, 0x9B, 0x11, 0x19, 0x9C, 0xED, 0x04, 0x6F,
	  0xBD, 0x70, 0x2D, 0x5C, 0x8A, 0x32, 0xFF, 0x16,
	  0x22, 0x57, 0x30, 0x3B, 0xD4, 0x59, 0x9C, 0x01,
	  0xF0, 0xA3, 0x70, 0xA1, 0x6C, 0x16, 0xAC, 0xCC,
	  0x8C, 0xAD, 0xB0, 0xA0, 0xAF, 0xC7, 0xCC, 0x49,
	  0x4F, 0xD9, 0x5D, 0x32, 0x1C, 0x2A, 0xE8, 0x4E,
	  0x15, 0xE1, 0x26, 0x6C, 0xC4, 0xB8, 0x94, 0xE1 },
	/* e */
	1,
	{ 0x11 },
	/* d */
	64,
	{ 0x13, 0xE7, 0x85, 0xBE, 0x53, 0xB7, 0xA2, 0x8A,
	  0xE4, 0xC9, 0xEA, 0xEB, 0xAB, 0xF6, 0xCB, 0xAF,
	  0x81, 0xA8, 0x04, 0x00, 0xA2, 0xC8, 0x43, 0xAF,
	  0x21, 0x25, 0xCF, 0x8C, 0xCE, 0xF8, 0xD9, 0x0F,
	  0x10, 0x78, 0x4C, 0x1A, 0x26, 0x5D, 0x90, 0x18,
	  0x79, 0x90, 0x42, 0x83, 0x6E, 0xAE, 0x3E, 0x20,
	  0x0B, 0x0C, 0x5B, 0x6B, 0x8E, 0x31, 0xE5, 0xCF,
	  0xD6, 0xE0, 0xBB, 0x41, 0xC1, 0xB8, 0x2E, 0x17 },
	/* p */
	32,
	{ 0xED, 0xE4, 0x02, 0x90, 0xA4, 0xA4, 0x98, 0x0D,
	  0x45, 0xA2, 0xF3, 0x96, 0x09, 0xED, 0x7B, 0x40,
	  0xCD, 0xF6, 0x21, 0xCC, 0xC0, 0x1F, 0x83, 0x09,
	  0x56, 0x37, 0x97, 0xFB, 0x05, 0x5B, 0x87, 0xB7 },
	/* q */
	32,
	{ 0xF2, 0xC1, 0x64, 0xE8, 0x69, 0xF8, 0x5E, 0x54,
	  0x8F, 0xFD, 0x20, 0x8E, 0x6A, 0x23, 0x90, 0xF2,
	  0xAF, 0x57, 0x2F, 0x4D, 0x10, 0x80, 0x8E, 0x11,
	  0x3C, 0x61, 0x44, 0x33, 0x2B, 0xE0, 0x58, 0x27 },
	/* u */
	32,
	{ 0x68, 0x45, 0x00, 0x64, 0x32, 0x9D, 0x09, 0x6E,
	  0x0A, 0xD3, 0xF3, 0x8A, 0xFE, 0x15, 0x8C, 0x79,
	  0xAD, 0x84, 0x35, 0x05, 0x19, 0x2C, 0x19, 0x51,
	  0xAB, 0x83, 0xC7, 0xE8, 0x5C, 0xAC, 0xAD, 0x7A },
	/* exponent1 */
	32,
	{ 0x99, 0xED, 0xE3, 0x8A, 0xC4, 0xE2, 0xF8, 0xF9,
	  0x87, 0x69, 0x70, 0x70, 0x24, 0x8A, 0x9B, 0x0B,
	  0xD0, 0x90, 0x33, 0xFC, 0xF4, 0xC9, 0x18, 0x8D,
	  0x92, 0x23, 0xF8, 0xED, 0xB8, 0x2C, 0x2A, 0xA3 },
	/* exponent2 */
	32,
	{ 0xB9, 0xA2, 0xF2, 0xCF, 0xD8, 0x90, 0xC0, 0x9B,
	  0x04, 0xB2, 0x82, 0x4E, 0xC9, 0xA2, 0xBA, 0x22,
	  0xFE, 0x8D, 0xF6, 0xFE, 0xB2, 0x44, 0x30, 0x67,
	  0x88, 0x86, 0x9D, 0x90, 0x8A, 0xF6, 0xD9, 0xFF }
	};

static BOOLEAN pairwiseConsistencyTest( CONTEXT_INFO *contextInfoPtr )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int status;

	/* Encrypt with the public key */
	memset( buffer, 0, CRYPT_MAX_PKCSIZE );
	memcpy( buffer + 1, "abcde", 5 );
	status = rsaEncrypt( contextInfoPtr, buffer, 
						 bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits ) );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Decrypt with the private key */
	status = rsaDecrypt( contextInfoPtr, buffer, 
						 bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits ) );
	if( cryptStatusError( status ) )
		return( FALSE );
	return( !memcmp( buffer + 1, "abcde", 5 ) );
	}

int rsaSelfTest( void )
	{
	CONTEXT_INFO contextInfoPtr;
	PKC_INFO pkcInfoStorage, *pkcInfo;
	static const FAR_BSS CAPABILITY_INFO capabilityInfo = \
		{ CRYPT_ALGO_RSA, 0, NULL, 64, 128, 512, 0 };
	BYTE buffer[ 64 ];
	int status;

	/* Initialise the key components */
	memset( &contextInfoPtr, 0, sizeof( CONTEXT_INFO ) );
	memset( &pkcInfoStorage, 0, sizeof( PKC_INFO ) );
	contextInfoPtr.ctxPKC = pkcInfo = &pkcInfoStorage;
	BN_init( &pkcInfo->rsaParam_n );
	BN_init( &pkcInfo->rsaParam_e );
	BN_init( &pkcInfo->rsaParam_d );
	BN_init( &pkcInfo->rsaParam_p );
	BN_init( &pkcInfo->rsaParam_q );
	BN_init( &pkcInfo->rsaParam_u );
	BN_init( &pkcInfo->rsaParam_exponent1 );
	BN_init( &pkcInfo->rsaParam_exponent2 );
	BN_init( &pkcInfo->tmp1 );
	BN_init( &pkcInfo->tmp2 );
	BN_init( &pkcInfo->tmp3 );
	BN_CTX_init( &pkcInfo->bnCTX );
	BN_MONT_CTX_init( &pkcInfo->rsaParam_mont_n );
	BN_MONT_CTX_init( &pkcInfo->rsaParam_mont_p );
	BN_MONT_CTX_init( &pkcInfo->rsaParam_mont_q );
	contextInfoPtr.capabilityInfo = &capabilityInfo;
	initKeyWrite( &contextInfoPtr );	/* For calcKeyID() */
	BN_bin2bn( rsaTestKey.n, rsaTestKey.nLen, &pkcInfo->rsaParam_n );
	BN_bin2bn( rsaTestKey.e, rsaTestKey.eLen, &pkcInfo->rsaParam_e );
	BN_bin2bn( rsaTestKey.d, rsaTestKey.dLen, &pkcInfo->rsaParam_d );
	BN_bin2bn( rsaTestKey.p, rsaTestKey.pLen, &pkcInfo->rsaParam_p );
	BN_bin2bn( rsaTestKey.q, rsaTestKey.qLen, &pkcInfo->rsaParam_q );
	BN_bin2bn( rsaTestKey.u, rsaTestKey.uLen, &pkcInfo->rsaParam_u );
	BN_bin2bn( rsaTestKey.e1, rsaTestKey.e1Len, &pkcInfo->rsaParam_exponent1 );
	BN_bin2bn( rsaTestKey.e2, rsaTestKey.e2Len, &pkcInfo->rsaParam_exponent2 );

	/* Perform the test en/decryption of a block of data */
	status = rsaInitKey( &contextInfoPtr, NULL, 0 );
	if( cryptStatusOK( status ) && \
		!pairwiseConsistencyTest( &contextInfoPtr ) )
		status = CRYPT_ERROR;
	else
		{
		/* Try it again with blinding enabled */
		memset( buffer, 0, 64 );
		memcpy( buffer, "abcde", 5 );
		contextInfoPtr.flags |= CONTEXT_SIDECHANNELPROTECTION;
		status = rsaInitKey( &contextInfoPtr, NULL, 0 );
		if( cryptStatusOK( status ) )
			status = rsaEncrypt( &contextInfoPtr, buffer, 64 );
		if( cryptStatusOK( status ) )
			status = rsaDecrypt( &contextInfoPtr, buffer, 64 );
		if( cryptStatusError( status ) || memcmp( buffer, "abcde", 5 ) )
			status = CRYPT_ERROR;
		else
			{
			/* And one last time to ensure that the blinding value update 
			   works */
			memset( buffer, 0, 64 );
			memcpy( buffer, "abcde", 5 );
			status = rsaInitKey( &contextInfoPtr, NULL, 0 );
			if( cryptStatusOK( status ) )
				status = rsaEncrypt( &contextInfoPtr, buffer, 64 );
			if( cryptStatusOK( status ) )
				status = rsaDecrypt( &contextInfoPtr, buffer, 64 );
			if( cryptStatusError( status ) || memcmp( buffer, "abcde", 5 ) )
				status = CRYPT_ERROR;
			}
		}

	/* Clean up */
	BN_clear_free( &pkcInfo->rsaParam_n );
	BN_clear_free( &pkcInfo->rsaParam_e );
	BN_clear_free( &pkcInfo->rsaParam_d );
	BN_clear_free( &pkcInfo->rsaParam_p );
	BN_clear_free( &pkcInfo->rsaParam_q );
	BN_clear_free( &pkcInfo->rsaParam_u );
	BN_clear_free( &pkcInfo->rsaParam_exponent1 );
	BN_clear_free( &pkcInfo->rsaParam_exponent2 );
	BN_clear_free( &pkcInfo->tmp1 );
	BN_clear_free( &pkcInfo->tmp2 );
	BN_clear_free( &pkcInfo->tmp3 );
	BN_CTX_free( &pkcInfo->bnCTX );
	BN_MONT_CTX_free( &pkcInfo->rsaParam_mont_n );
	BN_MONT_CTX_free( &pkcInfo->rsaParam_mont_p );
	BN_MONT_CTX_free( &pkcInfo->rsaParam_mont_q );
	zeroise( &pkcInfoStorage, sizeof( PKC_INFO ) );
	zeroise( &contextInfoPtr, sizeof( CONTEXT_INFO ) );

	return( status );
	}

/****************************************************************************
*																			*
*							Encrypt/Decrypt a Data Block					*
*																			*
****************************************************************************/

/* Encrypt/signature check a single block of data  */

int rsaEncrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BIGNUM *n = &pkcInfo->rsaParam_n, *e = &pkcInfo->rsaParam_e;
	BIGNUM *data = &pkcInfo->tmp1;
	const int length = bitsToBytes( pkcInfo->keySizeBits );
	int i, bnStatus = BN_STATUS;

	assert( noBytes == length );

	/* Make sure that we're not being fed suspiciously short data 
	   quantities */
	for( i = 0; i < length; i++ )
		if( buffer[ i ] )
			break;
	if( length - i < 56 )
		return( CRYPT_ERROR_BADDATA );

	/* Move the data from the buffer into a bignum, perform the modexp, and
	   move the result back into the buffer.  Since the bignum code performs
	   leading-zero truncation, we have to adjust where we copy the result to
	   in the buffer to take into account extra zero bytes that aren't
	   extracted from the bignum */
	BN_bin2bn( buffer, length, data );
	zeroise( buffer, length );	/* Clear buffer while data is in bignum */
	CK( BN_mod_exp_mont( data, data, e, n, &pkcInfo->bnCTX, 
						 &pkcInfo->rsaParam_mont_n ) );
	BN_bn2bin( data, buffer + ( length - BN_num_bytes( data ) ) );

	return( getBnStatus( bnStatus ) );
	}

/* Use the Chinese Remainder Theorem shortcut for RSA decryption/signature
   generation.  n isn't needed because of this.
   
   There are two types of side-channel attack protection that we employ for
   prvate-key operations, the first being standard blinding included in the 
   code below.  The second type applies to CRT-based RSA implementations and 
   is based on the fact that if a fault occurs during the computation of p2 
   or q2 (to give, say, p2') then applying the CRT will yield a faulty 
   signature M'.  An attacker can then compute q from 
   gcd( M' ** e - ( C mod n ), n ), and the same for q2' and p.  The chances
   of this actually occurring are... unlikely, given that it requires a
   singleton failure inside the CPU (with data running over ECC-protected
   buses) at the exact moment of CRT computation (the original threat model
   assumed a fault-injection attack on a smart card), however we can still 
   provide protection against the problem for people who consider it a
   genuine threat.

   The problem was originally pointed out by Marc Joye, Arjen Lenstra, and
   Jean-Jacques Quisquater in "Chinese Remaindering Based Cryptosystems in
   the Presence of Faults", Journal of Cryptology, Vol.12, No.4 (Autumn 
   1999), p.241, based on an earlier result "On the importance of checking
   cryptographic protocols for faults", Dan Boneh, Richard DeMillo, and
   Richard Lipton, EuroCrypt'97, LNCS Vol.1233, p.37.  Adi Shamir presented
   one possible solution to the problem in the conference's rump session in 
   "How to check modular exponentiation", which performs a parallel 
   computation of the potentially fault-affected portions of the CRT 
   operation in blinded form and then checks that the two outputs are
   consistent.  This has three drawbacks: It's slow, Shamir patented it
   (US Patent 5,991,415), and if one CRT is faulty there's no guarantee
   that the parallel CRT won't be faulty as well.  Better solutions were
   suggested by Sung-Ming Yen, Seungjoo Kim, Seongan Lim, and Sangjae
   Moon in "RSA Speedup with Residue Number System Immune against Hardware
   Fault Cryptanalysis", ICISC'01, LNCS Vol.2288, p.397.  These have less
   overhead than Shamir's approach and are also less patented, but like
   Shamir's approach they involve messing around with the CRT computation.  
   A further update to this given by Sung-Ming Yen, Sangjae Kim, and Jae-
   Cheol Ha in "Hardware Fault Attack on RSA with CRT Revisited", ICISC'02, 
   LNCS Vol.2587, p.374, which updated the earlier work and also found flaws 
   in Shamir's solution.
   
   A much simpler solution is just to verify the CRT-based private-key
   operation with the matching public-key operation after we perform it.  
   Since this is only required for signatures (the output of a decrypt is 
   (a) never visible to an attacker and (b) verified via the PKCS #1 
   padding), we perform this operation at a higher level, performing a 
   signature verify after each signature generation at the crypto mechanism 
   level */

int rsaDecrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BIGNUM *p = &pkcInfo->rsaParam_p, *q = &pkcInfo->rsaParam_q;
	BIGNUM *u = &pkcInfo->rsaParam_u, *e1 = &pkcInfo->rsaParam_exponent1;
	BIGNUM *e2 = &pkcInfo->rsaParam_exponent2;
	BIGNUM *data = &pkcInfo->tmp1, *p2 = &pkcInfo->tmp2, *q2 = &pkcInfo->tmp3;
	const int length = bitsToBytes( pkcInfo->keySizeBits );
	int i, bnStatus = BN_STATUS;

	assert( noBytes == length );

	/* Make sure that we're not being fed suspiciously short data quantities.  
	   We need to make one unfortunate exception for this to handle SSL's 
	   weird signatures, which sign a raw concatenated MD5 and SHA-1 hash 
	   with a total length of 36 bytes */
	for( i = 0; i < length; i++ )
		if( buffer[ i ] )
			break;
	if( ( length - i < 56 ) && ( length - i ) != 36 )
		return( CRYPT_ERROR_BADDATA );

	BN_bin2bn( buffer, length, data );
	zeroise( buffer, length );	/* Clear buffer while data is in bignum */

	/* If we're blinding the RSA operation, set 
	   data = ( ( rand^e ) * data ) mod n */
	if( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION )
		CK( BN_mod_mul( data, data, &pkcInfo->rsaParam_blind_k, 
						&pkcInfo->rsaParam_n, &pkcInfo->bnCTX ) );

	/* Rather than decrypting by computing a modexp with full mod n 
	   precision, compute a shorter modexp with mod p and mod q precision:
		p2 = ( ( C mod p ) ** exponent1 ) mod p
		q2 = ( ( C mod q ) ** exponent2 ) mod q */
	CK( BN_mod( p2, data, p,			/* p2 = C mod p  */
				&pkcInfo->bnCTX ) );
	CK( BN_mod_exp_mont( p2, p2, e1, p, &pkcInfo->bnCTX, 
						 &pkcInfo->rsaParam_mont_p ) );
	CK( BN_mod( q2, data, q,			/* q2 = C mod q  */
				&pkcInfo->bnCTX ) );
	CK( BN_mod_exp_mont( q2, q2, e2, q, &pkcInfo->bnCTX, 
						 &pkcInfo->rsaParam_mont_q ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* p2 = p2 - q2; if p2 < 0 then p2 = p2 + p.  In some extremely rare 
	   cases (q2 large, p2 small) we have to add p twice to get p2 
	   positive */
	CK( BN_sub( p2, p2, q2 ) );
	while( p2->neg )
		{
		CK( BN_add( p2, p2, p ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		}

	/* M = ( ( ( p2 * u ) mod p ) * q ) + q2 */
	CK( BN_mod_mul( data, p2, u, p,		/* data = ( p2 * u ) mod p */
					&pkcInfo->bnCTX ) );
	CK( BN_mul( p2, data, q,			/* p2 = data * q (bn can't reuse data) */
				&pkcInfo->bnCTX ) );
	CK( BN_add( data, p2, q2 ) );		/* data = p2 + q2 */
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* If we're blinding the RSA operation, set 
	   data = ( ( data^e ) / rand ) mod n 
			= ( rand^-1 * data ) mod n */
	if( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION )
		{
		BIGNUM *n = &pkcInfo->rsaParam_n;
		BIGNUM *k = &pkcInfo->rsaParam_blind_k;
		BIGNUM *kInv = &pkcInfo->rsaParam_blind_kInv;

		CK( BN_mod_mul( data, data, kInv, n, &pkcInfo->bnCTX ) );
		
		/* Update the blinding values in such a way that we get new random
		   (that is, unpredictable to an outsider) numbers of the correct
		   form without having to do a full modexp as we would if starting
		   with new random data:
	
			k = ( k^2 ) mod n */
		CK( BN_mod_mul( k, k, k, n, &pkcInfo->bnCTX ) );
		CK( BN_mod_mul( kInv, kInv, kInv, n, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		}

	/* Copy the result to the output buffer.  Since the bignum code performs 
	   leading-zero truncation, we have to adjust where we copy the result 
	   to in the buffer to take into account extra zero bytes that aren't 
	   extracted from the bignum */
	BN_bn2bin( data, buffer + ( length - BN_num_bytes( data ) ) );

	return( getBnStatus( bnStatus ) );
	}

/****************************************************************************
*																			*
*								Load Key Components							*
*																			*
****************************************************************************/

/* Load key components into an encryption context */

int rsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
				const int keyLength )
	{
	int status;

#ifndef USE_FIPS140
	/* Load the key component from the external representation into the
	   internal bignums unless we're doing an internal load */
	if( key != NULL )
		{
		PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
		const CRYPT_PKCINFO_RSA *rsaKey = ( CRYPT_PKCINFO_RSA * ) key;

		contextInfoPtr->flags |= ( rsaKey->isPublicKey ) ? \
							CONTEXT_ISPUBLICKEY : CONTEXT_ISPRIVATEKEY;
		BN_bin2bn( rsaKey->n, bitsToBytes( rsaKey->nLen ),
				   &pkcInfo->rsaParam_n );
		BN_bin2bn( rsaKey->e, bitsToBytes( rsaKey->eLen ),
				   &pkcInfo->rsaParam_e );
		if( !rsaKey->isPublicKey )
			{
			BN_bin2bn( rsaKey->d, bitsToBytes( rsaKey->dLen ),
					   &pkcInfo->rsaParam_d );
			BN_bin2bn( rsaKey->p, bitsToBytes( rsaKey->pLen ),
					   &pkcInfo->rsaParam_p );
			BN_bin2bn( rsaKey->q, bitsToBytes( rsaKey->qLen ),
					   &pkcInfo->rsaParam_q );
			BN_bin2bn( rsaKey->u, bitsToBytes( rsaKey->uLen ),
					   &pkcInfo->rsaParam_u );
			BN_bin2bn( rsaKey->e1, bitsToBytes( rsaKey->e1Len ),
					   &pkcInfo->rsaParam_exponent1 );
			BN_bin2bn( rsaKey->e2, bitsToBytes( rsaKey->e2Len ),
					   &pkcInfo->rsaParam_exponent2 );
			}
		contextInfoPtr->flags |= CONTEXT_PBO;
		}
#endif /* USE_FIPS140 */

	/* Complete the key checking and setup */
	status = initCheckRSAkey( contextInfoPtr );
	if( cryptStatusOK( status ) )
		status = calculateKeyID( contextInfoPtr );
	return( status );
	}

/* Generate a key into an encryption context */

int rsaGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits )
	{
	int status;

	status = generateRSAkey( contextInfoPtr, keySizeBits );
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

