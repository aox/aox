/****************************************************************************
*																			*
*							  PGP Support Routines							*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

/****************************************************************************
*																			*
*						PGP <-> Cryptlib Algorithm Conversion				*
*																			*
****************************************************************************/

/* Convert algorithm IDs from cryptlib to PGP and back */

typedef struct {
	const int pgpAlgo;
	const PGP_ALGOCLASS_TYPE pgpAlgoClass;
	const CRYPT_ALGO_TYPE cryptlibAlgo;
	} PGP_ALGOMAP_INFO;
static const PGP_ALGOMAP_INFO FAR_BSS pgpAlgoMap[] = {
	/* Encryption algos */
	{ PGP_ALGO_3DES, PGP_ALGOCLASS_CRYPT, CRYPT_ALGO_3DES },
	{ PGP_ALGO_BLOWFISH, PGP_ALGOCLASS_CRYPT, CRYPT_ALGO_BLOWFISH },
	{ PGP_ALGO_CAST5, PGP_ALGOCLASS_CRYPT, CRYPT_ALGO_CAST },
	{ PGP_ALGO_IDEA, PGP_ALGOCLASS_CRYPT, CRYPT_ALGO_IDEA },
	{ PGP_ALGO_AES_128, PGP_ALGOCLASS_CRYPT, CRYPT_ALGO_AES },
	{ PGP_ALGO_AES_192, PGP_ALGOCLASS_CRYPT, CRYPT_ALGO_AES },
	{ PGP_ALGO_AES_256, PGP_ALGOCLASS_CRYPT, CRYPT_ALGO_AES },

	/* Password-based encryption algos */
	{ PGP_ALGO_3DES, PGP_ALGOCLASS_PWCRYPT, CRYPT_ALGO_3DES },
	{ PGP_ALGO_BLOWFISH, PGP_ALGOCLASS_PWCRYPT, CRYPT_ALGO_BLOWFISH },
	{ PGP_ALGO_CAST5, PGP_ALGOCLASS_PWCRYPT, CRYPT_ALGO_CAST },
	{ PGP_ALGO_IDEA, PGP_ALGOCLASS_PWCRYPT, CRYPT_ALGO_IDEA },
	{ PGP_ALGO_AES_128, PGP_ALGOCLASS_PWCRYPT, CRYPT_ALGO_AES },
	{ PGP_ALGO_AES_192, PGP_ALGOCLASS_PWCRYPT, CRYPT_ALGO_AES },
	{ PGP_ALGO_AES_256, PGP_ALGOCLASS_PWCRYPT, CRYPT_ALGO_AES },

	/* PKC encryption algos */
	{ PGP_ALGO_RSA, PGP_ALGOCLASS_PKCCRYPT, CRYPT_ALGO_RSA },
	{ PGP_ALGO_RSA_ENCRYPT, PGP_ALGOCLASS_PKCCRYPT, CRYPT_ALGO_RSA },
	{ PGP_ALGO_ELGAMAL, PGP_ALGOCLASS_PKCCRYPT, CRYPT_ALGO_ELGAMAL },

	/* PKC sig algos */
	{ PGP_ALGO_RSA, PGP_ALGOCLASS_SIGN, CRYPT_ALGO_RSA },
	{ PGP_ALGO_RSA_SIGN, PGP_ALGOCLASS_SIGN, CRYPT_ALGO_RSA },
	{ PGP_ALGO_DSA, PGP_ALGOCLASS_SIGN, CRYPT_ALGO_DSA },

	/* Hash algos */
	{ PGP_ALGO_MD2, PGP_ALGOCLASS_HASH, CRYPT_ALGO_MD2 },
	{ PGP_ALGO_MD5, PGP_ALGOCLASS_HASH, CRYPT_ALGO_MD5 },
	{ PGP_ALGO_SHA, PGP_ALGOCLASS_HASH, CRYPT_ALGO_SHA },
	{ PGP_ALGO_RIPEMD160, PGP_ALGOCLASS_HASH, CRYPT_ALGO_RIPEMD160 },
	{ PGP_ALGO_SHA2_256, PGP_ALGOCLASS_HASH, CRYPT_ALGO_SHA2 },

	{ PGP_ALGO_NONE, 0, CRYPT_ALGO_NONE },
	{ PGP_ALGO_NONE, 0, CRYPT_ALGO_NONE }
	};

CRYPT_ALGO_TYPE pgpToCryptlibAlgo( const int pgpAlgo,
								   const PGP_ALGOCLASS_TYPE pgpAlgoClass )
	{
	int i;

	assert( pgpAlgoClass > PGP_ALGOCLASS_NONE && \
			pgpAlgoClass < PGP_ALGOCLASS_LAST );

	for( i = 0;
		 ( pgpAlgoMap[ i ].pgpAlgo != pgpAlgo || \
		   pgpAlgoMap[ i ].pgpAlgoClass != pgpAlgoClass ) && \
			pgpAlgoMap[ i ].pgpAlgo != PGP_ALGO_NONE && \
			i < FAILSAFE_ARRAYSIZE( pgpAlgoMap, PGP_ALGOMAP_INFO ); 
		 i++ );
	if( i >= FAILSAFE_ARRAYSIZE( pgpAlgoMap, PGP_ALGOMAP_INFO ) )
		retIntError_Ext( CRYPT_ALGO_NONE );
	return( pgpAlgoMap[ i ].cryptlibAlgo );
	}

int cryptlibToPgpAlgo( const CRYPT_ALGO_TYPE cryptlibAlgo )
	{
	int i;

	assert( cryptlibAlgo > CRYPT_ALGO_NONE && \
			cryptlibAlgo < CRYPT_ALGO_LAST );

	for( i = 0; 
		 pgpAlgoMap[ i ].cryptlibAlgo != cryptlibAlgo && \
			pgpAlgoMap[ i ].cryptlibAlgo != CRYPT_ALGO_NONE && \
			i < FAILSAFE_ARRAYSIZE( pgpAlgoMap, PGP_ALGOMAP_INFO ); 
		 i++ );
	if( i >= FAILSAFE_ARRAYSIZE( pgpAlgoMap, PGP_ALGOMAP_INFO ) )
		retIntError_Ext( PGP_ALGO_NONE );
	return( pgpAlgoMap[ i ].pgpAlgo );
	}

/****************************************************************************
*																			*
*							Misc. PGP-related Routines						*
*																			*
****************************************************************************/

/* Create an encryption key from a password */

int pgpPasswordToKey( CRYPT_CONTEXT iCryptContext, const int optKeyLength,
					  const char *password, const int passwordLength,
					  const CRYPT_ALGO_TYPE hashAlgo, const BYTE *salt,
					  const int iterations )
	{
	CRYPT_ALGO_TYPE algorithm;
	MESSAGE_DATA msgData;
	BYTE hashedKey[ CRYPT_MAX_KEYSIZE + 8 ];
	int keySize, status;

	assert( isHandleRangeValid( iCryptContext ) );
	assert( ( optKeyLength == CRYPT_UNUSED ) || \
			( optKeyLength >= 8 && optKeyLength <= CRYPT_MAX_KEYSIZE ) );
	assert( isReadPtr( password, passwordLength ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			hashAlgo <= CRYPT_ALGO_LAST_HASH );
	assert( ( salt == NULL ) || isReadPtr( salt, PGP_SALTSIZE ) );
	assert( iterations >= 0 );

	/* Get various parameters needed to process the password */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &keySize, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( algorithm == CRYPT_ALGO_BLOWFISH )
		/* PGP limits the Blowfish key size to 128 bits rather than the more
		   usual 448 bits */
		keySize = 16;
	if( algorithm == CRYPT_ALGO_AES && optKeyLength != CRYPT_UNUSED )
		/* PGP allows various AES key sizes and then encodes the size in the
		   algorithm ID (ugh), to handle this we allow the caller to specify
		   the actual size */
		keySize = optKeyLength;

	/* Hash the password */
	if( salt != NULL )
		{
		MECHANISM_DERIVE_INFO mechanismInfo;

		/* Turn the user key into an encryption context key */
		setMechanismDeriveInfo( &mechanismInfo, hashedKey, keySize,
								password, passwordLength, hashAlgo,
								salt, PGP_SALTSIZE, iterations );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
								  &mechanismInfo, MECHANISM_DERIVE_PGP );
		if( cryptStatusError( status ) )
			return( status );

		/* Save the derivation info with the context */
		setMessageData( &msgData, ( void * ) salt, PGP_SALTSIZE );
		krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEYING_SALT );
		krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE,
						 ( void * ) &iterations, CRYPT_CTXINFO_KEYING_ITERATIONS );
		status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &hashAlgo, CRYPT_CTXINFO_KEYING_ALGO );
		if( cryptStatusError( status ) )
			{
			zeroise( hashedKey, CRYPT_MAX_KEYSIZE );
			return( status );
			}
		}
	else
		{
		HASHFUNCTION hashFunction;

		getHashParameters( hashAlgo, &hashFunction, NULL );
		hashFunction( NULL, hashedKey, CRYPT_MAX_KEYSIZE, 
					  ( BYTE * ) password, passwordLength, HASH_ALL );
		}

	/* Load the key into the context */
	setMessageData( &msgData, hashedKey, keySize );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_KEY );
	zeroise( hashedKey, CRYPT_MAX_KEYSIZE );

	return( status );
	}

/* Process a PGP-style IV.  This isn't a standard IV but contains an extra
   two bytes of check value, which is why it's denoted as 'ivInfo' rather
   than a pure 'iv' */

int pgpProcessIV( const CRYPT_CONTEXT iCryptContext, BYTE *ivInfo,
				  const int ivSize, const BOOLEAN isEncrypt,
				  const BOOLEAN resyncIV )
	{
	static const BYTE zeroIV[ CRYPT_MAX_IVSIZE ] = { 0 };
	MESSAGE_DATA msgData;
	int status;

	assert( isHandleRangeValid( iCryptContext ) );
	assert( isReadPtr( ivInfo, ivSize ) );

	/* PGP uses a bizarre way of handling IV's that resyncs the data on
	   some boundaries, and doesn't actually use an IV but instead prefixes
	   the data with ivSize bytes of random information (which is effectively
	   the IV) followed by two bytes of key check value after which there's a
	   resync boundary that requires reloading the IV from the last ivSize
	   bytes of ciphertext.  An exception is the encrypted private key,
	   which does use an IV (although this can also be regarded as an
	   ivSize-byte prefix), however there's no key check or resync.  First,
	   we load the all-zero IV */
	setMessageData( &msgData, ( void * ) zeroIV, ivSize );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_IV );
	if( cryptStatusError( status ) )
		return( status );

	/* Then we encrypt or decrypt the first ivSize + 2 bytes of the IV
	   data */
	if( isEncrypt )
		{
		/* Get some random data to serve as the IV, duplicate the last two
		   bytes, and encrypt the lot */
		setMessageData( &msgData, ivInfo, ivSize );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusOK( status ) )
			{
			memcpy( ivInfo + ivSize, ivInfo + ivSize - 2, 2 );
			status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT,
									  ivInfo, ivSize + 2 );
			}
		}
	else
		{
		BYTE ivInfoBuffer[ CRYPT_MAX_IVSIZE + 2 + 8 ];

		/* Decrypt the first ivSize bytes (the effective IV) and following
		   2-byte check value.  There's a potential problem here in which an
		   attacker that convinces us to act as an oracle for the valid/not
		   valid status of the checksum can determine the contents of 16
		   bits of the encrypted data in 2^15 queries on average.  This is
		   incredibly unlikely, however if it's a concern then one
		   ameliorating change would be to not perform the check for keys
		   that were PKC-encrypted, because the PKC decryption process
		   would  check the key for us */
		memcpy( ivInfoBuffer, ivInfo, ivSize + 2 );
		status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_DECRYPT,
								  ivInfoBuffer, ivSize + 2 );
		if( cryptStatusOK( status ) && \
			( ivInfoBuffer[ ivSize - 2 ] != ivInfoBuffer[ ivSize ] || \
			  ivInfoBuffer[ ivSize - 1 ] != ivInfoBuffer[ ivSize + 1 ] ) )
			status = CRYPT_ERROR_WRONGKEY;
		}
	if( cryptStatusError( status ) || !resyncIV )
		return( status );

	/* Finally we've got the data the way we want it, resync the IV by
	   setting it to the last ivSize bytes of data processed unless we've
	   been told not to */
	setMessageData( &msgData, ivInfo + 2, ivSize );
	return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
							 &msgData, CRYPT_CTXINFO_IV ) );
	}
#endif /* USE_PGP || USE_PGPKEYS */
