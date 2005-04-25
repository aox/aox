/****************************************************************************
*																			*
*				cryptlib Key Derivation Mechanism Routines					*
*					Copyright Peter Gutmann 1992-2004						*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef INC_ALL
  #include "crypt.h"
  #include "pgp.h"
  #include "asn1.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../envelope/pgp.h"
  #include "../misc/asn1.h"
#else
  #include "crypt.h"
  #include "envelope/pgp.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#ifdef USE_PKCS12

/* Concantenate enough copies of input data together to fill an output
   buffer */

static void expandData( BYTE *outPtr, const int outLen, const BYTE *inPtr,
						const int inLen )
	{
	int remainder = outLen;

	while( remainder > 0 )
		{
		const int bytesToCopy = min( inLen, remainder );

		memcpy( outPtr, inPtr, bytesToCopy );
		outPtr += bytesToCopy;
		remainder -= bytesToCopy;
		}
	}
#endif /* USE_PKCS12 */

/****************************************************************************
*																			*
*							Key Derivation Mechanisms						*
*																			*
****************************************************************************/

/* HMAC-based PRF used for PKCS #5 v2 and TLS */

#define HMAC_DATASIZE		64

static void prfInit( HASHFUNCTION hashFunction, void *hashState,
					 const int hashSize, void *processedKey,
					 int *processedKeyLength, const void *key,
					 const int keyLength )
	{
	BYTE hashBuffer[ HMAC_DATASIZE ], *keyPtr = processedKey;
	int i;

	/* If the key size is larger than tha SHA data size, reduce it to the
	   SHA hash size before processing it (yuck.  You're required to do this
	   though) */
	if( keyLength > HMAC_DATASIZE )
		{
		/* Hash the user key down to the hash size and use the hashed form of
		   the key */
		hashFunction( NULL, processedKey, ( void * ) key, keyLength, HASH_ALL );
		*processedKeyLength = hashSize;
		}
	else
		{
		/* Copy the key to internal storage */
		memcpy( processedKey, key, keyLength );
		*processedKeyLength = keyLength;
		}

	/* Perform the start of the inner hash using the zero-padded key XORed
	   with the ipad value */
	memset( hashBuffer, HMAC_IPAD, HMAC_DATASIZE );
	for( i = 0; i < *processedKeyLength; i++ )
		hashBuffer[ i ] ^= *keyPtr++;
	hashFunction( hashState, NULL, hashBuffer, HMAC_DATASIZE, HASH_START );
	zeroise( hashBuffer, HMAC_DATASIZE );
	}

static void prfEnd( HASHFUNCTION hashFunction, void *hashState,
					const int hashSize, void *hash,
					const void *processedKey, const int processedKeyLength )
	{
	BYTE hashBuffer[ HMAC_DATASIZE ], digestBuffer[ CRYPT_MAX_HASHSIZE ];
	int i;

	/* Complete the inner hash and extract the digest */
	hashFunction( hashState, digestBuffer, NULL, 0, HASH_END );

	/* Perform the outer hash using the zero-padded key XORed with the opad
	   value followed by the digest from the inner hash */
	memset( hashBuffer, HMAC_OPAD, HMAC_DATASIZE );
	memcpy( hashBuffer, processedKey, processedKeyLength );
	for( i = 0; i < processedKeyLength; i++ )
		hashBuffer[ i ] ^= HMAC_OPAD;
	hashFunction( hashState, NULL, hashBuffer, HMAC_DATASIZE, HASH_START );
	zeroise( hashBuffer, HMAC_DATASIZE );
	hashFunction( hashState, hash, digestBuffer, hashSize, HASH_END );
	zeroise( digestBuffer, CRYPT_MAX_HASHSIZE );
	}

/* Perform PKCS #5 v2 derivation */

int derivePKCS5( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	const CRYPT_ALGO_TYPE hmacAlgo = \
				( mechanismInfo->hashAlgo == CRYPT_ALGO_HMAC_MD5 ) ? \
					CRYPT_ALGO_MD5 : \
				( mechanismInfo->hashAlgo == CRYPT_ALGO_HMAC_RIPEMD160 ) ? \
					CRYPT_ALGO_RIPEMD160 : CRYPT_ALGO_SHA;
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo, initialHashInfo;
	BYTE processedKey[ HMAC_DATASIZE ], block[ CRYPT_MAX_HASHSIZE ];
	BYTE countBuffer[ 4 ];
	BYTE *dataOutPtr = mechanismInfo->dataOut;
	int hashSize, keyIndex, processedKeyLength, blockCount = 1;

	UNUSED( dummy );

	/* Set up the block counter buffer.  This will never have more than the
	   last few bits set (8 bits = 5100 bytes of key) so we only change the
	   last byte */
	memset( countBuffer, 0, 4 );

	/* Initialise the HMAC information with the user key.  Although the user
	   has specified the algorithm in terms of an HMAC, we're synthesising it
	   from the underlying hash algorithm since this allows us to perform the
	   PRF setup once and reuse it for any future hashing since it's
	   constant */
	getHashParameters( hmacAlgo, &hashFunction, &hashSize );
	prfInit( hashFunction, initialHashInfo, hashSize,
			 processedKey, &processedKeyLength,
			 mechanismInfo->dataIn, mechanismInfo->dataInLength );

	/* Produce enough blocks of output to fill the key */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength;
		 keyIndex += hashSize, dataOutPtr += hashSize )
		{
		const int noKeyBytes = \
			( mechanismInfo->dataOutLength - keyIndex > hashSize ) ? \
			hashSize : mechanismInfo->dataOutLength - keyIndex;
		int i;

		/* Calculate HMAC( salt || counter ) */
		countBuffer[ 3 ] = ( BYTE ) blockCount++;
		memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
		hashFunction( hashInfo, NULL, mechanismInfo->salt,
					  mechanismInfo->saltLength, HASH_CONTINUE );
		hashFunction( hashInfo, NULL, countBuffer, 4, HASH_CONTINUE );
		prfEnd( hashFunction, hashInfo, hashSize, block, processedKey,
				processedKeyLength );
		memcpy( dataOutPtr, block, noKeyBytes );

		/* Calculate HMAC( T1 ) ^ HMAC( T1 ) ^ ... HMAC( Tc ) */
		for( i = 0; i < mechanismInfo->iterations - 1; i++ )
			{
			int j;

			/* Generate the PRF output for the current iteration */
			memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
			hashFunction( hashInfo, NULL, block, hashSize, HASH_CONTINUE );
			prfEnd( hashFunction, hashInfo, hashSize, block, processedKey,
					processedKeyLength );

			/* Xor the new PRF output into the existing PRF output */
			for( j = 0; j < noKeyBytes; j++ )
				dataOutPtr[ j ] ^= block[ j ];
			}
		}
	zeroise( hashInfo, sizeof( HASHINFO ) );
	zeroise( initialHashInfo, sizeof( HASHINFO ) );
	zeroise( processedKey, HMAC_DATASIZE );
	zeroise( block, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

#ifdef USE_PKCS12

/* Perform PKCS #12 derivation */

#define P12_BLOCKSIZE	64

int derivePKCS12( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION hashFunction;
	BYTE p12_DSP[ P12_BLOCKSIZE + P12_BLOCKSIZE + ( P12_BLOCKSIZE * 3 ) ];
	BYTE p12_Ai[ P12_BLOCKSIZE ], p12_B[ P12_BLOCKSIZE ];
	BYTE *bmpPtr = p12_DSP + P12_BLOCKSIZE + P12_BLOCKSIZE;
	BYTE *dataOutPtr = mechanismInfo->dataOut;
	const BYTE *dataInPtr = mechanismInfo->dataIn;
	const BYTE *saltPtr = mechanismInfo->salt;
	const int bmpLen = ( mechanismInfo->dataInLength * 2 ) + 2;
	const int p12_PLen = ( mechanismInfo->dataInLength <= 30 ) ? \
							P12_BLOCKSIZE : \
						 ( mechanismInfo->dataInLength <= 62 ) ? \
							( P12_BLOCKSIZE * 2 ) : ( P12_BLOCKSIZE * 3 );
	int hashSize, keyIndex, i;

	UNUSED( dummy );

	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

	/* Set up the diversifier in the first P12_BLOCKSIZE bytes, the salt in
	   the next P12_BLOCKSIZE bytes, and the password as a Unicode null-
	   terminated string in the final bytes */
	for( i = 0; i < P12_BLOCKSIZE; i++ )
		p12_DSP[ i ] = saltPtr[ 0 ];
	expandData( p12_DSP + P12_BLOCKSIZE, P12_BLOCKSIZE, saltPtr + 1,
				mechanismInfo->saltLength - 1 );
	for( i = 0; i < mechanismInfo->dataInLength; i++ )
		{
		*bmpPtr++ = '\0';
		*bmpPtr++ = dataInPtr[ i ];
		}
	*bmpPtr++ = '\0';
	*bmpPtr++ = '\0';
	expandData( p12_DSP + ( P12_BLOCKSIZE * 2 ) + bmpLen, p12_PLen - bmpLen,
				p12_DSP + ( P12_BLOCKSIZE * 2 ), bmpLen );

	/* Produce enough blocks of output to fill the key */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength;
		 keyIndex += hashSize, dataOutPtr += hashSize )
		{
		const int noKeyBytes = \
			( mechanismInfo->dataOutLength - keyIndex > hashSize ) ? \
			hashSize : mechanismInfo->dataOutLength - keyIndex;
		BYTE *p12_DSPj;

		/* Hash the keying material the required number of times to obtain the
		   output value */
		hashFunction( NULL, p12_Ai, p12_DSP,
					  P12_BLOCKSIZE + P12_BLOCKSIZE + p12_PLen, HASH_ALL );
		for( i = 1; i < mechanismInfo->iterations; i++ )
			hashFunction( NULL, p12_Ai, p12_Ai, hashSize, HASH_ALL );
		memcpy( dataOutPtr, p12_Ai, noKeyBytes );
		if( noKeyBytes <= hashSize)
			break;

		/* Update the input keying material for the next iteration */
		expandData( p12_B, P12_BLOCKSIZE, p12_Ai, hashSize );
		for( p12_DSPj = p12_DSP + P12_BLOCKSIZE; 
			 p12_DSPj < p12_DSP + ( 2 * P12_BLOCKSIZE ) + p12_PLen; 
			 p12_DSPj += P12_BLOCKSIZE )
			{
			int dspIndex = P12_BLOCKSIZE - 1, bIndex = P12_BLOCKSIZE - 1;
			int carry = 1;

			/* Ij = (Ij + B + 1) mod 2^BLOCKSIZE */
			for( dspIndex = P12_BLOCKSIZE - 1, bIndex = P12_BLOCKSIZE - 1;
				 dspIndex >= 0; dspIndex--, bIndex-- )
				{
				const int value = p12_DSPj[ dspIndex ] + p12_B[ bIndex ] + carry;
				p12_DSPj[ dspIndex ] = value & 0xFF;
				carry = value >> 8;
				}
			}
		}
	zeroise( p12_DSP, P12_BLOCKSIZE + P12_BLOCKSIZE + ( P12_BLOCKSIZE * 3 ) );
	zeroise( p12_Ai, P12_BLOCKSIZE );
	zeroise( p12_B, P12_BLOCKSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_PKCS12 */

#ifdef USE_SSL

/* Perform SSL key derivation */

int deriveSSL( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION md5HashFunction, shaHashFunction;
	HASHINFO hashInfo;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], counterData[ 16 ];
	int md5HashSize, shaHashSize, counter = 0, keyIndex;

	UNUSED( dummy );

	getHashParameters( CRYPT_ALGO_MD5, &md5HashFunction, &md5HashSize );
	getHashParameters( CRYPT_ALGO_SHA, &shaHashFunction, &shaHashSize );

	/* Produce enough blocks of output to fill the key */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength;
		 keyIndex += md5HashSize )
		{
		const int noKeyBytes = \
			( mechanismInfo->dataOutLength - keyIndex > md5HashSize ) ? \
			md5HashSize : mechanismInfo->dataOutLength - keyIndex;
		int i;

		/* Set up the counter data */
		for( i = 0; i <= counter; i++ )
			counterData[ i ] = 'A' + counter;
		counter++;

		/* Calculate SHA1( 'A'/'BB'/'CCC'/... || keyData || salt ) */
		shaHashFunction( hashInfo, NULL, counterData, counter, HASH_START );
		shaHashFunction( hashInfo, NULL, mechanismInfo->dataIn,
						 mechanismInfo->dataInLength, HASH_CONTINUE );
		shaHashFunction( hashInfo, hash, mechanismInfo->salt,
						 mechanismInfo->saltLength, HASH_END );

		/* Calculate MD5( keyData || SHA1-hash ) */
		md5HashFunction( hashInfo, NULL, mechanismInfo->dataIn,
						 mechanismInfo->dataInLength, HASH_START );
		md5HashFunction( hashInfo, hash, hash, shaHashSize, HASH_END );

		/* Copy the result to the output */
		memcpy( ( BYTE * )( mechanismInfo->dataOut ) + keyIndex, hash, noKeyBytes );
		}
	zeroise( hashInfo, sizeof( HASHINFO ) );
	zeroise( hash, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* Perform TLS key derivation (this is the function described as PRF() in the
   TLS spec) */

int deriveTLS( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION md5HashFunction, shaHashFunction;
	HASHINFO md5HashInfo, md5InitialHashInfo, md5AnHashInfo;
	HASHINFO shaHashInfo, shaInitialHashInfo, shaAnHashInfo;
	BYTE md5ProcessedKey[ HMAC_DATASIZE ], shaProcessedKey[ HMAC_DATASIZE ];
	BYTE md5A[ CRYPT_MAX_HASHSIZE ], shaA[ CRYPT_MAX_HASHSIZE ];
	BYTE md5Hash[ CRYPT_MAX_HASHSIZE ], shaHash[ CRYPT_MAX_HASHSIZE ];
	BYTE *md5DataOutPtr = mechanismInfo->dataOut;
	BYTE *shaDataOutPtr = mechanismInfo->dataOut;
	const BYTE *dataEndPtr = ( BYTE * ) mechanismInfo->dataOut + \
							 mechanismInfo->dataOutLength;
	const void *s1, *s2;
	const int sLen = ( mechanismInfo->dataInLength + 1 ) / 2;
	int md5ProcessedKeyLength, shaProcessedKeyLength;
	int md5HashSize, shaHashSize, keyIndex;

	UNUSED( dummy );

	getHashParameters( CRYPT_ALGO_MD5, &md5HashFunction, &md5HashSize );
	getHashParameters( CRYPT_ALGO_SHA, &shaHashFunction, &shaHashSize );

	/* Find the start of the two halves of the keying info used for the
	   HMAC'ing.  The size of each half is given by
	   ceil( dataInLength / 2 ), so there's a one-byte overlap if the input
	   is an odd number of bytes long */
	s1 = mechanismInfo->dataIn;
	s2 = ( BYTE * ) mechanismInfo->dataIn + ( mechanismInfo->dataInLength - sLen );

	/* The two hash functions have different block sizes that would require
	   complex buffering to handle leftover bytes from SHA-1, a simpler
	   method is to zero the output data block and XOR in the values from
	   each hash mechanism using separate output location indices for MD5 and
	   SHA-1 */
	memset( mechanismInfo->dataOut, 0, mechanismInfo->dataOutLength );

	/* Initialise the MD5 and SHA-1 information with the keying info.  These
	   are reused for any future hashing since they're constant */
	prfInit( md5HashFunction, md5InitialHashInfo, md5HashSize,
			 md5ProcessedKey, &md5ProcessedKeyLength, s1, sLen );
	prfInit( shaHashFunction, shaInitialHashInfo, shaHashSize,
			 shaProcessedKey, &shaProcessedKeyLength, s2, sLen );

	/* Calculate A1 = HMAC( salt ) */
	memcpy( md5HashInfo, md5InitialHashInfo, sizeof( HASHINFO ) );
	md5HashFunction( md5HashInfo, NULL, mechanismInfo->salt,
					 mechanismInfo->saltLength, HASH_CONTINUE );
	prfEnd( md5HashFunction, md5HashInfo, md5HashSize, md5A,
			md5ProcessedKey, md5ProcessedKeyLength );
	memcpy( shaHashInfo, shaInitialHashInfo, sizeof( HASHINFO ) );
	shaHashFunction( shaHashInfo, NULL, mechanismInfo->salt,
					 mechanismInfo->saltLength, HASH_CONTINUE );
	prfEnd( shaHashFunction, shaHashInfo, shaHashSize, shaA,
			shaProcessedKey, shaProcessedKeyLength );

	/* Produce enough blocks of output to fill the key.  We use the MD5 hash
	   size as the loop increment since this produces the smaller output
	   block */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength;
		 keyIndex += md5HashSize )
		{
		const int md5NoKeyBytes = \
					min( ( dataEndPtr - md5DataOutPtr ), md5HashSize );
		const int shaNoKeyBytes = \
					min( ( dataEndPtr - shaDataOutPtr ), shaHashSize );
		int i;		/* Spurious ()'s needed for broken compilers */

		/* Calculate HMAC( An || salt ) */
		memcpy( md5HashInfo, md5InitialHashInfo, sizeof( HASHINFO ) );
		md5HashFunction( md5HashInfo, NULL, md5A, md5HashSize, HASH_CONTINUE );
		memcpy( md5AnHashInfo, md5HashInfo, sizeof( HASHINFO ) );
		md5HashFunction( md5HashInfo, NULL, mechanismInfo->salt,
						 mechanismInfo->saltLength, HASH_CONTINUE );
		prfEnd( md5HashFunction, md5HashInfo, md5HashSize, md5Hash,
				md5ProcessedKey, md5ProcessedKeyLength );
		memcpy( shaHashInfo, shaInitialHashInfo, sizeof( HASHINFO ) );
		shaHashFunction( shaHashInfo, NULL, shaA, shaHashSize, HASH_CONTINUE );
		memcpy( shaAnHashInfo, shaHashInfo, sizeof( HASHINFO ) );
		shaHashFunction( shaHashInfo, NULL, mechanismInfo->salt,
						 mechanismInfo->saltLength, HASH_CONTINUE );
		prfEnd( shaHashFunction, shaHashInfo, shaHashSize, shaHash,
				shaProcessedKey, shaProcessedKeyLength );

		/* Calculate An+1 = HMAC( An ) */
		memcpy( md5HashInfo, md5AnHashInfo, sizeof( HASHINFO ) );
		prfEnd( md5HashFunction, md5HashInfo, md5HashSize, md5A,
				md5ProcessedKey, md5ProcessedKeyLength );
		memcpy( shaHashInfo, shaAnHashInfo, sizeof( HASHINFO ) );
		prfEnd( shaHashFunction, shaHashInfo, shaHashSize, shaA,
				shaProcessedKey, shaProcessedKeyLength );

		/* Copy the result to the output */
		for( i = 0; i < md5NoKeyBytes; i++ )
			md5DataOutPtr[ i ] ^= md5Hash[ i ];
		for( i = 0; i < shaNoKeyBytes; i++ )
			shaDataOutPtr[ i ] ^= shaHash[ i ];
		md5DataOutPtr += md5NoKeyBytes;
		shaDataOutPtr += shaNoKeyBytes;
		}
	zeroise( md5HashInfo, sizeof( HASHINFO ) );
	zeroise( md5InitialHashInfo, sizeof( HASHINFO ) );
	zeroise( md5AnHashInfo, sizeof( HASHINFO ) );
	zeroise( shaHashInfo, sizeof( HASHINFO ) );
	zeroise( shaInitialHashInfo, sizeof( HASHINFO ) );
	zeroise( shaAnHashInfo, sizeof( HASHINFO ) );
	zeroise( md5ProcessedKey, HMAC_DATASIZE );
	zeroise( shaProcessedKey, HMAC_DATASIZE );
	zeroise( md5A, CRYPT_MAX_HASHSIZE );
	zeroise( shaA, CRYPT_MAX_HASHSIZE );
	zeroise( md5Hash, CRYPT_MAX_HASHSIZE );
	zeroise( shaHash, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_SSL */

#ifdef USE_CMP

/* Perform CMP/Entrust key derivation */

int deriveCMP( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo;
	int hashSize, iterations = mechanismInfo->iterations - 1;

	UNUSED( dummy );

	/* Calculate SHA1( password || salt ) */
	getHashParameters( mechanismInfo->hashAlgo, &hashFunction, &hashSize );
	hashFunction( hashInfo, NULL, mechanismInfo->dataIn,
				  mechanismInfo->dataInLength, HASH_START );
	hashFunction( hashInfo, mechanismInfo->dataOut, mechanismInfo->salt,
				  mechanismInfo->saltLength, HASH_END );

	/* Iterate the hashing the remaining number of times */
	while( iterations-- )
		hashFunction( NULL, mechanismInfo->dataOut, mechanismInfo->dataOut,
					  hashSize, HASH_ALL );
	zeroise( hashInfo, sizeof( HASHINFO ) );

	return( CRYPT_OK );
	}
#endif /* USE_CMP */

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

/* Perform OpenPGP S2K key derivation */

int derivePGP( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo;
	BYTE hashedKey[ CRYPT_MAX_KEYSIZE ];
	long byteCount = ( long ) mechanismInfo->iterations << 6;
	long secondByteCount = 0;
	int hashSize;

	getHashParameters( mechanismInfo->hashAlgo, &hashFunction, &hashSize );

	/* If it's a non-iterated hash or the count won't allow even a single
	   pass over the 8-byte salt and password, adjust it to make sure that 
	   we run at least one full iteration */
	if( byteCount < PGP_SALTSIZE + mechanismInfo->dataInLength )
		byteCount = PGP_SALTSIZE + mechanismInfo->dataInLength;

	/* If the hash output size is less than the required key size, run a
	   second round of hashing after the first one to provide the required
	   amount of keying material */
	if( hashSize < mechanismInfo->dataOutLength )
		secondByteCount = byteCount;

	/* Repeatedly hash the salt and password until we've met the byte count */
	hashFunction( hashInfo, NULL, mechanismInfo->salt,
				  mechanismInfo->saltLength, HASH_START );
	byteCount -= mechanismInfo->saltLength;
	do
		{
		if( byteCount <= mechanismInfo->dataInLength )
			hashFunction( hashInfo, hashedKey, mechanismInfo->dataIn,
						  byteCount, HASH_END );
		else
			hashFunction( hashInfo, NULL, mechanismInfo->dataIn,
						  mechanismInfo->dataInLength, HASH_CONTINUE );
		byteCount -= mechanismInfo->dataInLength;
		if( byteCount <= 0 )
			continue;
		if( byteCount <= mechanismInfo->saltLength )
			hashFunction( hashInfo, hashedKey, mechanismInfo->salt,
						  byteCount, HASH_END );
		else
			hashFunction( hashInfo, NULL, mechanismInfo->salt,
						  mechanismInfo->saltLength, HASH_CONTINUE );
		byteCount -= mechanismInfo->saltLength;
		}
	while( byteCount > 0 );
	if( secondByteCount )
		{
		/* Perform a second round of hashing, preloading the hash with a
		   single zero byte */
		hashFunction( hashInfo, NULL, ( const BYTE * ) "\x00", 1,
					  HASH_START );
		do
			{
			if( secondByteCount <= mechanismInfo->saltLength )
				hashFunction( hashInfo, hashedKey + hashSize,
							  mechanismInfo->salt, secondByteCount,
							  HASH_END );
			else
				hashFunction( hashInfo, NULL, mechanismInfo->salt,
							  mechanismInfo->saltLength, HASH_CONTINUE );
			secondByteCount -= mechanismInfo->saltLength;
			if( secondByteCount <= 0 )
				continue;
			if( secondByteCount <= mechanismInfo->dataInLength )
				hashFunction( hashInfo, hashedKey + hashSize,
							  mechanismInfo->dataIn, secondByteCount,
							  HASH_END );
			else
				hashFunction( hashInfo, NULL, mechanismInfo->dataIn,
							  mechanismInfo->dataInLength, HASH_CONTINUE );
			secondByteCount -= mechanismInfo->dataInLength;
			}
		while( secondByteCount > 0 );
		}
	memcpy( mechanismInfo->dataOut, hashedKey, mechanismInfo->dataOutLength );
	zeroise( hashInfo, sizeof( HASHINFO ) );
	zeroise( hashedKey, CRYPT_MAX_KEYSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_PGP || USE_PGPKEYS */
