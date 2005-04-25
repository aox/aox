/****************************************************************************
*																			*
*							  PGP Key Read Routines							*
*						Copyright Peter Gutmann 1992-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "pgp.h"
  #include "keyset.h"
  #include "misc_rw.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../envelope/pgp.h"
  #include "keyset.h"
  #include "../misc/misc_rw.h"
#else
  #include "crypt.h"
  #include "envelope/pgp.h"
  #include "keyset/keyset.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

#ifdef USE_PGPKEYS

/* A PGP private key file can contain multiple key objects, before we do
   anything with the file we scan it and build an in-memory index of what's
   present.  When we perform an update we just flush the in-memory
   information to disk.

   Each file can contain information for multiple personalities (although
   for private keys it's unlikely to contain more than a small number), we 
   allow a maximum of MAX_PGP_OBJECTS per file.  A setting of 16 objects 
   consumes ~4K of memory (16 x ~256), so we choose that as the limit */

#ifdef CONFIG_CONSERVE_MEMORY
  #define MAX_PGP_OBJECTS	4
#else
  #define MAX_PGP_OBJECTS	16
#endif /* CONFIG_CONSERVE_MEMORY */

/* Each PGP key can contain an arbitrary number of user IDs, we only track
   the following maximum number.  Further IDs are read and stored, but not
   indexed or searched on */

#define MAX_PGP_USERIDS		16

/* When reading a PGP keyring, we implement a sliding window that reads a
   certain amount of data into a lookahead buffer and then tries to identify
   a key packet group in the buffer.  The following value determines the size
   of the lookahead.  Unfortunately we have to keep this above a certain
   minimum size in order to handle PGP 8.x's inclusion of photo IDs in 
   keyrings, which means that the smallest size we can safely use is about 
   8kb */

#define KEYRING_BUFSIZE		8192

/* Key-related information needed to create a cryptlib context from PGP key
   data */

typedef struct {
	/* Key data information */
	CRYPT_ALGO_TYPE pkcAlgo;		/* Key algorithm */
	int usageFlags;					/* Keymgmt flags permitted usage */
	BYTE pgpKeyID[ PGP_KEYID_SIZE ], openPGPkeyID[ PGP_KEYID_SIZE ];
	void *pubKeyData, *privKeyData;	/* Pointer to encoded pub/priv key data */
	int pubKeyDataLen, privKeyDataLen;

	/* Key data protection information */
	CRYPT_ALGO_TYPE cryptAlgo;		/* Key wrap algorithm */
	int aesKeySize;					/* Key size if algo == AES */
	BYTE iv[ CRYPT_MAX_IVSIZE ];	/* Key wrap IV */
	CRYPT_ALGO_TYPE hashAlgo;		/* Password hashing algo */
	BYTE salt[ PGP_SALTSIZE ];		/* Password hashing salt */
	int saltSize;
	int keySetupIterations;			/* Password hashing iterations */
	} PGP_KEYINFO;

/* The following structure contains the the information for one personality,
   which covers one or more of a private key, public key, and subkeys.  PGP
   encodes keys in a complex manner by writing them as groups of (implicitly)
   connected packets that require arbitrary amounts of lookahead to parse.  
   To handle this we read the overall encoded key data as a single unit and
   store it in a dynamically-allocated buffer, then set up pointers to
   locations of relevant data (public and private keys and user IDs) within
   the overall key data.  To further complicate matters, there can be a key
   and subkey associated with the same information, so we have to maintain
   two lots of physical keying information for each logical key */

typedef struct {
	void *keyData;					/* Encoded key data */
	int keyDataLen;
	PGP_KEYINFO key, subKey;		/* Key and subkey information */
	char *userID[ MAX_PGP_USERIDS ];/* UserIDs */
	int userIDlen[ MAX_PGP_USERIDS ];
	int lastUserID;					/* Last used userID */
	BOOLEAN isOpenPGP;				/* Whether data is PGP 2.x or OpenPGP */
	} PGP_INFO;

/* When we're searching for a key, we need to compare each one against a
   collection of match criteria.  The following struct contains the 
   information that we match against */

typedef struct {
	CONST_INIT CRYPT_KEYID_TYPE keyIDtype;/* Key ID type */
	const void *keyID;
	CONST_INIT int keyIDlength;		/* Key ID */
	CONST_INIT int flags;			/* Key usage flags */
	} KEY_MATCH_INFO;

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get the size of an encoded MPI and skip the payload data */

static int getMPIsize( STREAM *stream )
	{
	int bitLength, length;

	/* Read the MPI length and make sure that it's in order */
	bitLength = readUint16( stream );
	length = bitsToBytes( bitLength );
	if( length < 1 || length > PGP_MAX_MPISIZE || \
		length > sMemDataLeft( stream ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( 0 );	/* Dummy value */
		}

	sSkip( stream, length );
	return( 2 + length );
	}

/* Scan a sequence of key packets to find the extent of the packet group.  In
   addition to simply scanning, this function handles over-long packets by
   reporting their overall length and returning OK_SPECIAL, and will try to 
   resync to a packet group if it starts in the middle of an arbitrary packet 
   collection, for example due to skipping of an over-long packet found 
   earlier */

static int scanPacketGroup( const void *data, const int dataLength,
							int *packetGroupLength )
	{
	STREAM stream;
	BOOLEAN firstPacket = TRUE, skipPackets = FALSE;
	int endPos = 0, status = CRYPT_OK;

	/* Clear return value */
	*packetGroupLength = 0;

	sMemConnect( &stream, data, dataLength );
	do
		{
		long length;
		int ctb;

		/* Get the next CTB.  If it's the start of another packet group,
		   we're done */
		ctb = status = sPeek( &stream );
		if( cryptStatusOK( status ) )
			{
			assert( ctb & PGP_CTB );
			if( !( ctb & PGP_CTB ) )
				status = CRYPT_ERROR_BADDATA;
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		if( firstPacket )
			{
			/* If the packet group doesn't start with the expected packet
			   type, skip packets to try to resync */
			if( getCTB( ctb ) != PGP_PACKET_PUBKEY && \
				getCTB( ctb ) != PGP_PACKET_SECKEY )
				skipPackets = TRUE;
			firstPacket = FALSE;
			}
		else
			if( getCTB( ctb ) == PGP_PACKET_PUBKEY || \
				getCTB( ctb ) == PGP_PACKET_SECKEY )
				{
				/* We've found the start of a new packet group, remember 
				   where the current group ends and exit */
				sMemDisconnect( &stream );
				*packetGroupLength = endPos;
				return( skipPackets ? OK_SPECIAL : CRYPT_OK );
				}

		/* Skip the current packet in the buffer */
		status = pgpReadPacketHeader( &stream, NULL, &length );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		endPos = stell( &stream ) + length;
		sSkip( &stream, length );
		}
	while( endPos < dataLength );
	sMemDisconnect( &stream );
	*packetGroupLength = endPos;

	/* If we skipped packets or consumed all the input in the buffer and 
	   there's more present beyond that, tell the caller to discard the
	   data and try again */
	return( ( skipPackets || endPos > dataLength ) ? OK_SPECIAL : CRYPT_OK );
	}

/* Free object entries */

static void pgpFreeEntry( PGP_INFO *pgpInfo )
	{
	if( pgpInfo->keyData != NULL )
		{
		zeroise( pgpInfo->keyData, pgpInfo->keyDataLen );
		clFree( "pgpFreeEntry", pgpInfo->keyData );
		pgpInfo->keyData = NULL;
		pgpInfo->keyDataLen = 0;
		}
	zeroise( pgpInfo, sizeof( PGP_INFO  ) );
	}

/****************************************************************************
*																			*
*									Find a Key								*
*																			*
****************************************************************************/

/* Generate a cryptlib-style key ID for a PGP key and check it against the
   given key ID.  This will really suck with large public keyrings since it
   requires creating a context for each key we check, but there's no easy
   way around this, and in any case it only occurs when using PGP keys with
   non-PGP messages, which is fairly rare */

static BOOLEAN matchKeyID( const PGP_KEYINFO *keyInfo, const BYTE *requiredID,
						   const int requiredIDlength,
						   const BOOLEAN isPGPkeyID )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	BYTE keyID[ KEYID_SIZE ];
	int status;

	/* If it's a PGP key ID, we can check it directly against the two PGP
	   key IDs.  We don't distinguish between the two ID types externally
	   because it's a pain for external code to have to know that there are
	   two ID types that look the same and are often used interchangeably, 
	   but only the OpenPGP variant is valid for all keys (in fact there 
	   are some broken PGP variants that use PGP 2.x IDs marked as OpenPGP 
	   IDs, so checking both IDs is necessary for interoperability).  The 
	   mixing of ID types is safe because the chances of a collision are 
	   miniscule, and the worst that can possibly happen is that a sig check 
	   will fail (encryption keys are chosen by user ID and not key ID, so 
	   accidentally using the wrong key to encrypt isn't an issue) */
	if( isPGPkeyID )
		{
		assert( requiredIDlength == PGP_KEYID_SIZE );

		if( !memcmp( requiredID, keyInfo->openPGPkeyID, PGP_KEYID_SIZE ) )
			return( TRUE );
		return( ( keyInfo->pkcAlgo == CRYPT_ALGO_RSA ) && \
				!memcmp( requiredID, keyInfo->pgpKeyID, PGP_KEYID_SIZE ) );
		}

	assert( requiredIDlength == KEYID_SIZE );

	/* Generate the key ID via a context.  We have to set the OpenPGP key ID
	   before the key load to mark it as a PGP key, otherwise the key 
	   check will fail since it's not a full X9.42 key with DLP validation 
	   parameters */
	setMessageCreateObjectInfo( &createInfo, keyInfo->pkcAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( void * ) keyInfo->openPGPkeyID, 
						PGP_KEYID_SIZE );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, keyInfo->pubKeyData,
							keyInfo->pubKeyDataLen );
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_SETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_KEY_PGP );
			}
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, keyID, KEYID_SIZE );
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_IATTRIBUTE_KEYID );
			}
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		}
	if( cryptStatusError( status ) )
		{
		assert( NOTREACHED );
		return( FALSE );
		}

	/* Check if it's the same as the key ID we're looking for */
	return( !memcmp( requiredID, keyID, requiredIDlength ) ? TRUE : FALSE );
	}

/* Match a substring of a full string as done by PGP */

static BOOLEAN matchSubstring( const char *subString,
							   const int subStringLength,
							   const char *string, const int stringLength )
	{
	const char firstChar = toUpper( subString[ 0 ] );
	int i;

	/* Perform a case-insensitive match for the required substring in the
	   string */
	for( i = 0; i <= stringLength - subStringLength; i++ )
		if( ( toUpper( string[ i ] ) == firstChar ) &&
			!strCompare( subString, string + i, subStringLength ) )
				return( TRUE );

	return( FALSE );
	}

/* Check whether a key matches the required user ID */

static BOOLEAN checkKeyMatch( const PGP_INFO *pgpInfo, 
							  const PGP_KEYINFO *keyInfo,
							  const KEY_MATCH_INFO *keyMatchInfo )
	{
	int i;

	/* If there's an explicitly requested key usage type, make sure that the 
	   key is suitable */
	if( ( keyMatchInfo->flags & KEYMGMT_MASK_USAGEOPTIONS ) && \
		!( keyInfo->usageFlags & keyMatchInfo->flags ) )
		return( FALSE );

	/* If we're searching by key ID, check whether this is the packet we
	   want */
	if( keyMatchInfo->keyIDtype == CRYPT_IKEYID_KEYID || \
		keyMatchInfo->keyIDtype == CRYPT_IKEYID_PGPKEYID )
		return( matchKeyID( keyInfo, keyMatchInfo->keyID, 
					keyMatchInfo->keyIDlength,
					( keyMatchInfo->keyIDtype == CRYPT_IKEYID_PGPKEYID ) ? \
						TRUE : FALSE ) );

	assert( keyMatchInfo->keyIDtype == CRYPT_KEYID_NAME || \
			keyMatchInfo->keyIDtype == CRYPT_KEYID_URI );

	/* We're searching by user ID, walk down the list of userIDs checking
	   for a match */
	for( i = 0; i < pgpInfo->lastUserID; i++ )
		/* Check if it's the one we want.  If it's a key with subkeys and no
		   usage type is explicitly specified, this will always return the
		   main key.  This is the best solution since the main key is always
		   a signing key, which is more likely to be what the user wants.
		   Encryption keys will typically only be accessed via envelopes,
		   and the enveloping code can specify a preference of an encryption-
		   capable key, while signing keys will be read directly and pushed
		   into the envelope */
		if( matchSubstring( ( char * ) keyMatchInfo->keyID, 
							keyMatchInfo->keyIDlength, pgpInfo->userID[ i ],
							pgpInfo->userIDlen[ i ] ) )
			return( TRUE );

	return( FALSE );
	}

/* Locate a key based on an ID.  This is complicated somewhat by the fact 
   that PGP groups multiple keys around the same textual ID, so we have to 
   check both keys and subkeys for a possible match */

static PGP_INFO *findEntry( const PGP_INFO *pgpInfo,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID, const int keyIDlength,
							const int requestedUsage, PGP_KEYINFO **keyInfo )
	{
	CONST_INIT_STRUCT_4( KEY_MATCH_INFO keyMatchInfo, \
						 keyIDtype, keyID, keyIDlength, requestedUsage );
	int i;

	CONST_SET_STRUCT( keyMatchInfo.keyIDtype = keyIDtype; \
					  keyMatchInfo.keyID = keyID; \
					  keyMatchInfo.keyIDlength = keyIDlength; \
					  keyMatchInfo.flags = requestedUsage );

	for( i = 0; i < MAX_PGP_OBJECTS; i++ )
		{
		if( checkKeyMatch( &pgpInfo[ i ], &pgpInfo[ i ].key,
						   &keyMatchInfo ) )
			{
			if( keyInfo != NULL )
				*keyInfo = ( PGP_KEYINFO * ) &pgpInfo[ i ].key;
			return( ( PGP_INFO * ) &pgpInfo[ i ] );
			}
		if( checkKeyMatch( &pgpInfo[ i ], &pgpInfo[ i ].subKey,
						   &keyMatchInfo ) )
			{
			if( keyInfo != NULL )
				*keyInfo = ( PGP_KEYINFO * ) &pgpInfo[ i ].subKey;
			return( ( PGP_INFO * ) &pgpInfo[ i ] );
			}
		}

	return( NULL );
	}

/****************************************************************************
*																			*
*									Read a Key								*
*																			*
****************************************************************************/

/* Read the information needed to decrypt a secret key */

static int readSecretKeyDecryptionInfo( STREAM *stream, PGP_KEYINFO *keyInfo )
	{
	const int ctb = sgetc( stream );
	int ivSize = PGP_IVSIZE, status;

	/* Clear return value */
	keyInfo->cryptAlgo = keyInfo->hashAlgo = CRYPT_ALGO_NONE;
	keyInfo->saltSize = keyInfo->keySetupIterations = 0;

	/* If no encryption is being used, we mark the key as unusable.  This 
	   isn't exactly the correct thing to do, but storing plaintext private 
	   keys on disk is extremely dangerous and we probably shouldn't be
	   using them, and an attempt to import an unencrypted key will trigger
	   so many security check failures in the key unwrap code that it's not 
	   even worth trying */
	if( !ctb )
		return( OK_SPECIAL );

	/* If it's a direct algorithm specifier, it's a PGP 2.x packet with
	   raw IDEA encryption */
	if( ctb == PGP_ALGO_IDEA )
		{
		keyInfo->cryptAlgo = CRYPT_ALGO_IDEA;
		keyInfo->hashAlgo = CRYPT_ALGO_MD5;
		}
	else
		{
		int value;

		/* Must be an S2K specifier */
		if( ctb != PGP_S2K && ctb != PGP_S2K_HASHED )
			return( CRYPT_ERROR_BADDATA );

		/* Get the key wrap algorithm and S2K information */
		value = sgetc( stream );
		if( ( keyInfo->cryptAlgo = \
				pgpToCryptlibAlgo( value,
								   PGP_ALGOCLASS_PWCRYPT ) ) == CRYPT_ALGO_NONE )
			/* Unknown algorithm type, skip this packet */
			return( OK_SPECIAL );
		if( keyInfo->cryptAlgo == CRYPT_ALGO_AES )
			{
			/* PGP uses three different algorithm IDs to identify AES with
			   different key sizes (ugh), so we have to remember the key size
			   alongside the algorithm type for this algorithm type */
			keyInfo->aesKeySize = ( value == PGP_ALGO_AES_128 ) ? 16 : \
								  ( value == PGP_ALGO_AES_192 ) ? 24 : 32;
			ivSize = 16;
			}
		value = sgetc( stream );
		if( value != 0 && value != 1 && value != 3 )
			return( cryptStatusError( value ) ? value : OK_SPECIAL );
		if( ( keyInfo->hashAlgo = \
				pgpToCryptlibAlgo( sgetc( stream ),
								   PGP_ALGOCLASS_HASH ) ) == CRYPT_ALGO_NONE )
			/* Unknown algorithm type, skip this packet */
			return( OK_SPECIAL );
		if( value != 0 )
			{
			/* It's a salted hash */
			status = sread( stream, keyInfo->salt, PGP_SALTSIZE );
			if( cryptStatusError( status ) )
				return( status );
			keyInfo->saltSize = PGP_SALTSIZE;
			}
		if( value == 3 )
			{
			/* Salted iterated hash, get the iteration count, limited to a
			   sane value.  The "iteration count" is actually a count of how
			   many bytes are hashed, this is because the "iterated hashing"
			   treats the salt + password as an infinitely-repeated sequence
			   of values and hashes the resulting string for PGP-iteration-
			   count bytes worth.  The value we calculate here (to prevent
			   overflow on 16-bit machines) is the count without the
			   base * 64 scaling, this also puts the range within the value
			   of the standard sanity check */
			value = sgetc( stream );
			if( cryptStatusError( value ) )
				return( value );
			keyInfo->keySetupIterations = \
					( 16 + ( ( long ) value & 0x0F ) ) << ( value >> 4 );
			if( keyInfo->keySetupIterations <= 0 || \
				keyInfo->keySetupIterations > MAX_KEYSETUP_ITERATIONS )
				return( CRYPT_ERROR_BADDATA );
			}
		}
	status = sread( stream, keyInfo->iv, ivSize );
	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}

/* Read a single key in a group of key packets */

static int readKey( STREAM *stream, PGP_INFO *pgpInfo )
	{
	PGP_KEYINFO *keyInfo = &pgpInfo->key;
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], packetHeader[ 64 ];
	BOOLEAN isPublicKey = TRUE;
	void *pubKeyPayload;
	long packetLength;
	int startPos, endPos, ctb, length, pubKeyPayloadLen;
	int value, hashSize, status;

	/* Skip CTB, packet length, and version byte */
	ctb = sPeek( stream );
	switch( getCTB( ctb ) )
		{
		case PGP_PACKET_SECKEY_SUB:
			keyInfo = &pgpInfo->subKey;
			/* Fall through */

		case PGP_PACKET_SECKEY:
			isPublicKey = FALSE;
			break;

		case PGP_PACKET_PUBKEY_SUB:
			keyInfo = &pgpInfo->subKey;
			/* Fall through */

		case PGP_PACKET_PUBKEY:
			break;

		default:
			return( cryptStatusError( ctb ) ? \
					CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_BADDATA );
		}
	status = pgpReadPacketHeader( stream, NULL, &packetLength );
	if( cryptStatusError( status ) )
		return( status );
	if( packetLength < 64 || sMemDataLeft( stream ) < packetLength )
		return( CRYPT_ERROR_BADDATA );
	length = ( int ) packetLength;
	keyInfo->pubKeyData = sMemBufPtr( stream );
	startPos = stell( stream );
	endPos = startPos + length;
	value = sgetc( stream );
	if( value != PGP_VERSION_2 && value != PGP_VERSION_3 && \
		value != PGP_VERSION_OPENPGP )
		/* Unknown version number, skip this packet */
		return( OK_SPECIAL );
	pgpInfo->isOpenPGP = ( value == PGP_VERSION_OPENPGP ) ? TRUE : FALSE;

	/* Build the packet header, which is hashed along with the key components
	   to get the OpenPGP keyID.  This is generated anyway when the context
	   is created, but we need to generate it here as well in order to locate
	   the key in the first place:
		byte		ctb = 0x99
		byte[2]		length
		byte		version = 4
		byte[4]		key generation time
		byte[]		key data

	   We can't add the length or key data yet since we have to parse the
	   key data to know how long it is, so we can only build the static part
	   of the header at this point */
	packetHeader[ 0 ] = 0x99;
	packetHeader[ 3 ] = PGP_VERSION_OPENPGP;

	/* Read the timestamp and validity period (for PGP 2.x keys) */
	sread( stream, packetHeader + 4, 4 );
	if( !pgpInfo->isOpenPGP )
		sSkip( stream, 2 );

	/* Read the public key components */
	pubKeyPayload = sMemBufPtr( stream );
	pubKeyPayloadLen = stell( stream );
	value = sgetc( stream );
	if( value == PGP_ALGO_RSA || value == PGP_ALGO_RSA_ENCRYPT || \
		value == PGP_ALGO_RSA_SIGN )
		{
		/* RSA: n + e.  The LSBs of n serve as the PGP 2.x key ID, so we
		   copy the data out before continuing */
		keyInfo->pkcAlgo = CRYPT_ALGO_RSA;
		if( value != PGP_ALGO_RSA_SIGN )
			keyInfo->usageFlags = KEYMGMT_FLAG_USAGE_CRYPT;
		if( value != PGP_ALGO_RSA_ENCRYPT )
			keyInfo->usageFlags |= KEYMGMT_FLAG_USAGE_SIGN;
		length = 1 + getMPIsize( stream );
		if( sStatusOK( stream ) && \
			stell( stream ) - startPos > PGP_KEYID_SIZE )
			memcpy( keyInfo->pgpKeyID, sMemBufPtr( stream ) - PGP_KEYID_SIZE,
					PGP_KEYID_SIZE );
		length += getMPIsize( stream );
		}
	else
		{
		/* If it's an unknown algorithm, skip this key */
		if( value != PGP_ALGO_DSA && value != PGP_ALGO_ELGAMAL )
			return( cryptStatusError( value ) ? value: OK_SPECIAL );

		/* DSA/Elgamal: p + g + y */
		if( value == PGP_ALGO_DSA )
			{
			keyInfo->pkcAlgo = CRYPT_ALGO_DSA;
			keyInfo->usageFlags = KEYMGMT_FLAG_USAGE_SIGN;
			}
		else
			{
			keyInfo->pkcAlgo = CRYPT_ALGO_ELGAMAL;
			keyInfo->usageFlags = KEYMGMT_FLAG_USAGE_CRYPT;
			}
		length = 1 + getMPIsize( stream ) + getMPIsize( stream ) + \
				 getMPIsize( stream );
		if( value == PGP_ALGO_DSA )
			/* DSA has q as well */
			length += getMPIsize( stream );
		}
	status = sGetStatus( stream );
	if( cryptStatusError( status ) )
		return( status );
	keyInfo->pubKeyDataLen = stell( stream ) - startPos;
	pubKeyPayloadLen = stell( stream ) - pubKeyPayloadLen;

	/* Complete the packet header that we read earlier on by adding the
	   length information */
	packetHeader[ 1 ] = ( ( 1 + 4 + length ) >> 8 ) & 0xFF;
	packetHeader[ 2 ] = ( 1 + 4 + length ) & 0xFF;

	/* Hash the data needed to generate the OpenPGP keyID */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	hashFunction( hashInfo, NULL, packetHeader, 1 + 2 + 1 + 4, HASH_START );
	hashFunction( hashInfo, hash, pubKeyPayload, pubKeyPayloadLen, HASH_END );
	memcpy( keyInfo->openPGPkeyID, hash + hashSize - PGP_KEYID_SIZE,
			PGP_KEYID_SIZE );

	/* If it's a private keyring, process the private key components */
	if( !isPublicKey )
		{
		/* Handle decryption info for secret components if necessary */
		status = readSecretKeyDecryptionInfo( stream, keyInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* What's left is the private-key data */
		keyInfo->privKeyData = sMemBufPtr( stream );
		keyInfo->privKeyDataLen = endPos - stell( stream );
		status = sSkip( stream, keyInfo->privKeyDataLen );
		}

	/* Read the userID packet(s) */
	while( cryptStatusOK( status ) )
		{
		int type;

		/* Skip keyring trust packets, signature packets, and any private
		   packets (GPG uses packet type 61, which might be a DSA self-
		   signature).

		   PGP has two ways of indicating key usage, either directly via the
		   key type (e.g. PGP_ALGO_RSA_ENCRYPT vs. PGP_ALGO_RSA_SIGN) or in a
		   rather schizophrenic manner in signature packets by allowing the 
		   signer to specify an X.509-style key usage.  Since it can appear 
		   in both self-sigs and certification sigs, the exact usage for a 
		   key is somewhat complex to determine as a certification signer 
		   could indicate that they trust the key when it's used for signing 
		   while a self-signer could indicate that the key should be used 
		   for encryption.  This appears to be a preference indication 
		   rather than a hard limit like the X.509 keyUsage, and contains 
		   other odds and ends as well such as key splitting indicators.  
		   For now we don't make use of these flags as it's a bit difficult 
		   to figure out what's what, and in any case DSA vs. Elgamal 
		   doesn't need any further constraints since there's only one usage 
		   possible */
		while( cryptStatusOK( status ) )
			{
			/* See what we've got.  If we've run out of input or it's a non-
			   key-related packet, we're done */
			ctb = status = sPeek( stream );
			type = getCTB( ctb );
			if( cryptStatusError( status ) || \
				( type != PGP_PACKET_TRUST && type != PGP_PACKET_SIGNATURE && \
				  type != PGP_PACKET_USERATTR && !isPrivatePacket( type ) ) )
				break;

			/* Skip the packet.  If we get an error at this point, we don't
			   immediately bail out but try and return at least a partial
			   response */
			status = pgpReadPacketHeader( stream, &ctb, &packetLength );
			if( cryptStatusOK( status ) )
				status = sSkip( stream, packetLength );
			}

		/* If we've reached the end of the current collection of key
		   packets, exit */
		if( cryptStatusError( status ) || type != PGP_PACKET_USERID )
			{
			/* If there's no user ID present, set a generic label */
			if( pgpInfo->lastUserID == 0 )
				{
				pgpInfo->userID[ 0 ] = "PGP key (no user ID found)";
				pgpInfo->userIDlen[ 0 ] = 26;
				pgpInfo->lastUserID = 1;
				}

			return( CRYPT_OK );
			}

		/* Record the userID */
		status = pgpReadPacketHeader( stream, &ctb, &packetLength );
		if( cryptStatusError( status ) )
			return( status );
		pgpInfo->userID[ pgpInfo->lastUserID ] = sMemBufPtr( stream );
		pgpInfo->userIDlen[ pgpInfo->lastUserID++ ] = ( int ) packetLength;
		status = sSkip( stream, packetLength );
		}

	return( status );
	}

/* Process the information in the packet group */

static int processPacketGroup( STREAM *stream, PGP_INFO *pgpInfo,
							   const KEY_MATCH_INFO *keyMatchInfo,
							   PGP_KEYINFO **matchedKeyInfoPtrPtr )
	{
	int status;

	/* Clear the index info before we read the current keys, since it may 
	   already have been initialised during a previous (incomplete) key 
	   read */
	memset( &pgpInfo->key, 0, sizeof( PGP_KEYINFO ) );
	memset( &pgpInfo->subKey, 0, sizeof( PGP_KEYINFO ) );
	memset( pgpInfo->userID, 0, sizeof( char * ) * MAX_PGP_USERIDS );
	memset( pgpInfo->userIDlen, 0, sizeof( int ) * MAX_PGP_USERIDS );
	pgpInfo->lastUserID = 0;

	/* Read all the packets in this packet group */
	do
		status = readKey( stream, pgpInfo );
	while( cryptStatusOK( status ) && sMemDataLeft( stream ) > 0 );
	if( cryptStatusError( status ) )
		{
		if( status != OK_SPECIAL )
			return( status );

		/* There's something in the key information that we can't handle, 
		   mark the keyring as read-only and skip the key */
		if( keyMatchInfo == NULL )
			pgpFreeEntry( pgpInfo );
		return( OK_SPECIAL );
		}

	/* If we're reading all keys, we're done */
	if( keyMatchInfo == NULL )
		return( CRYPT_OK );

	/* We're searching for a particular key, see if this is the one */
	if( checkKeyMatch( pgpInfo, &pgpInfo->key, keyMatchInfo ) )
		{
		*matchedKeyInfoPtrPtr = &pgpInfo->key;
		return( CRYPT_OK );
		}
	if( checkKeyMatch( pgpInfo, &pgpInfo->subKey, keyMatchInfo ) )
		{
		*matchedKeyInfoPtrPtr = &pgpInfo->subKey;
		return( CRYPT_OK );
		}

	/* No match, tell the caller to keep looking */
	return( CRYPT_ERROR_NOTFOUND );
	}

/* Read an entire keyring.  This function can be used in one of two ways, if
   key match information is supplied each packet will be checked against it
   and the read will exit when a match is found.  If no key match info is
   supplied, all keys will be read into memory */

static int processKeyringPacketsMMapped( STREAM *stream, 
										 KEYSET_INFO *keysetInfo, 
										 const KEY_MATCH_INFO *keyMatchInfo,
										 PGP_KEYINFO **matchedKeyInfoPtrPtr )
	{
	PGP_INFO *pgpInfo = ( PGP_INFO * ) keysetInfo->keyData;
	int keyGroupNo = 0, status;

	assert( keyMatchInfo == NULL || \
			( pgpInfo->keyData != NULL && \
			  pgpInfo->keyDataLen == KEYRING_BUFSIZE ) );

	while( TRUE )
		{
		PGP_INFO *pgpInfoPtr = &pgpInfo[ keyGroupNo ];
		STREAM keyStream;
		int length;

		/* Determine the size of the group of key packets in the buffer */
		status = scanPacketGroup( sMemBufPtr( stream ), 
								  sMemDataLeft( stream ), &length );
		if( cryptStatusError( status ) )
			{
			if( status != OK_SPECIAL )
				return( status );

			/* We couldn't process one or more packets, make the keyset
			   read-only to ensure that the incomplete key data isn't 
			   written to disk */
			keysetInfo->options = CRYPT_KEYOPT_READONLY;
			}

		status = sFileToMemStream( &keyStream, stream, NULL, length );
		if( cryptStatusOK( status ) )
			status = processPacketGroup( &keyStream, pgpInfoPtr, keyMatchInfo,
										 matchedKeyInfoPtrPtr );
		sMemDisconnect( &keyStream );
		if( cryptStatusError( status ) )
			{
			/* If we were looking for a match for a particular key and 
			   didn't find it, continue */
			if( keyMatchInfo != NULL && status == CRYPT_ERROR_NOTFOUND )
				continue;

			if( status != OK_SPECIAL )
				return( status );

			/* There's something in the key information that we can't 
			   handle, mark the keyring as read-only */
			keysetInfo->options = CRYPT_KEYOPT_READONLY;
			status = CRYPT_OK;
			continue;
			}

		/* If we're looking for a particular key, we've found it */
		if( keyMatchInfo != NULL )
			return( CRYPT_OK );

		/* We're reading all keys, move on to the next empty slot */
		keyGroupNo++;
		if( keyGroupNo >= MAX_PGP_OBJECTS )
			return( CRYPT_ERROR_OVERFLOW );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processKeyringPackets( STREAM *stream, BYTE *buffer, 
								  KEYSET_INFO *keysetInfo, 
								  const KEY_MATCH_INFO *keyMatchInfo,
								  PGP_KEYINFO **matchedKeyInfoPtrPtr )
	{
	PGP_INFO *pgpInfo = ( PGP_INFO * ) keysetInfo->keyData;
	BYTE streamBuffer[ STREAM_BUFSIZE ];
	BOOLEAN moreData = TRUE;
	int bufEnd = 0, keyGroupNo = 0, status;

	assert( keyMatchInfo == NULL || \
			( pgpInfo->keyData != NULL && \
			  pgpInfo->keyDataLen == KEYRING_BUFSIZE ) );

	/* Scan all the objects in the file.  This is implemented as a sliding
	   window that reads a certain amount of data into a lookahead buffer
	   and then tries to identify a packet group in the buffer.  If we need
	   to skip packets (for example due to unknown algorithms), we mark the
	   keyset as read-only since it's no longer safe for us to write the
	   incompletely-processed data to disk */
	sioctl( stream, STREAM_IOCTL_IOBUFFER, streamBuffer, STREAM_BUFSIZE );
	while( moreData || bufEnd > 0 )
		{
		PGP_INFO *pgpInfoPtr = &pgpInfo[ keyGroupNo ];
		STREAM keyStream;
		int length;

		/* Fill the lookahead buffer */
		if( moreData )
			{
			status = length = sread( stream, buffer + bufEnd,
									 KEYRING_BUFSIZE - bufEnd );
			if( status <= 0 )
				{
				/* If we read nothing and there's nothing left in the buffer,
				   we're done */
				if( bufEnd <= 0 )
					{
					/* If we've previously read at least one group of key 
					   packets, we're OK */
					if( keyGroupNo > 0 )
						status = CRYPT_OK;
					return( status );
					}

				/* There's still data in the buffer, we can continue until 
				   we drain it */
				length = 0;
				}
			if( length < KEYRING_BUFSIZE - bufEnd )
				/* We didn't get as much as we requested, there's nothing
				   left to read */
				moreData = FALSE;
			bufEnd += length;
			}

		/* Determine the size of the group of key packets in the buffer */
		status = scanPacketGroup( buffer, bufEnd, &length );
		if( status == OK_SPECIAL )
			{
			/* We couldn't process one or more packets, make the keyset
			   read-only to ensure that the incomplete key data isn't 
			   written to disk */
			keysetInfo->options = CRYPT_KEYOPT_READONLY;

			/* If the packet group is contained within the buffer, remove 
			   the problem packets and continue */
			if( length <= bufEnd )
				{
				if( bufEnd - length > 0 )
					memmove( buffer, buffer + length, bufEnd - length );
				bufEnd -= length;
				continue;
				}

			/* The packet group overflows the buffer, skip the remaining
			   contents and continue */
			status = sseek( stream, stell( stream ) + ( length - bufEnd ) );
			if( cryptStatusError( status ) )
				break;
			bufEnd = 0;
			continue;
			}
		if( cryptStatusError( status ) || length <= 0 )
			return( status );

		/* Move the packet group from the keyring buffer to the key data */
		if( keyMatchInfo == NULL )
			{
			/* It's a read of all packets, allocate room for the current
			   packet group */
			if( ( pgpInfoPtr->keyData = \
								clAlloc( "readKeyring", length ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			pgpInfoPtr->keyDataLen = length;
			}
		memcpy( pgpInfoPtr->keyData, buffer, length );
		if( bufEnd - length > 0 )
			memmove( buffer, buffer + length, bufEnd - length );
		bufEnd -= length;

		/* Process the current packet group */
		sMemConnect( &keyStream, pgpInfoPtr->keyData, length );
		status = processPacketGroup( &keyStream, pgpInfoPtr, keyMatchInfo,
									 matchedKeyInfoPtrPtr );
		sMemDisconnect( &keyStream );
		if( cryptStatusError( status ) )
			{
			/* If we were looking for a match for a particular key and 
			   didn't find it, continue */
			if( keyMatchInfo != NULL && status == CRYPT_ERROR_NOTFOUND )
				continue;

			if( status != OK_SPECIAL )
				return( status );

			/* There's something in the key information that we can't 
			   handle, mark the keyring as read-only */
			keysetInfo->options = CRYPT_KEYOPT_READONLY;
			status = CRYPT_OK;
			continue;
			}

		/* If we're looking for a particular key, we've found it */
		if( keyMatchInfo != NULL )
			return( CRYPT_OK );

		/* We're reading all keys, move on to the next empty slot */
		keyGroupNo++;
		if( keyGroupNo >= MAX_PGP_OBJECTS )
			return( CRYPT_ERROR_OVERFLOW );
		}
	
	return( ( keyMatchInfo == NULL ) ? CRYPT_OK : CRYPT_ERROR_NOTFOUND );
	}

static int readKeyring( KEYSET_INFO *keysetInfo, 
						const KEY_MATCH_INFO *keyMatchInfo,
						PGP_KEYINFO **matchedKeyInfoPtrPtr )
	{
	STREAM *stream = &keysetInfo->keysetFile->stream;
	int status;

	assert( ( keyMatchInfo == NULL && matchedKeyInfoPtrPtr == NULL ) || \
			( keyMatchInfo != NULL && matchedKeyInfoPtrPtr != NULL ) );

	/* Clear the return value */
	if( matchedKeyInfoPtrPtr != NULL )
		*matchedKeyInfoPtrPtr = NULL;

	if( sIsMemMappedStream( stream ) )
		{
		status = processKeyringPacketsMMapped( stream, keysetInfo, 
											   keyMatchInfo, 
											   matchedKeyInfoPtrPtr );
		}
	else
		{
		BYTE *buffer;

		if( ( buffer = clAlloc( "readKeyring", KEYRING_BUFSIZE ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );

		/* Since PGP keyrings just contain an arbitrary collection of 
		   packets concatenated together, we can't tell in advance how much 
		   data we should be reading.  Because of this we have to set the 
		   file stream to allow partial reads without returning a read 
		   error */
		sioctl( stream, STREAM_IOCTL_PARTIALREAD, NULL, 0 );
		status = processKeyringPackets( stream, buffer, keysetInfo, 
										keyMatchInfo, matchedKeyInfoPtrPtr );
		sioctl( stream, STREAM_IOCTL_IOBUFFER, NULL, 0 );
		clFree( "readKeyring", buffer );
		}

	/* If we're reading all keys and the read failed, the keyring as a whole 
	   can't be used */
	if( keyMatchInfo == NULL && cryptStatusError( status ) )
		keysetInfo->shutdownFunction( keysetInfo );
	return( status );
	}

/* Read key data from a PGP keyring */

static int getItemFunction( KEYSET_INFO *keysetInfo,
							CRYPT_HANDLE *iCryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID,  const int keyIDlength,
							void *auxInfo, int *auxInfoLength,
							const int flags )
	{
	CRYPT_CONTEXT iSessionKey;
	PGP_INFO *pgpInfo = ( PGP_INFO * ) keysetInfo->keyData;
	PGP_KEYINFO *keyInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MECHANISM_WRAP_INFO mechanismInfo;
	RESOURCE_DATA msgData;
	int status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_PGPKEYID );

	/* Find the requested item.  This is complicated somewhat by the fact
	   that private keys are held in memory while public keys (which can
	   be arbitrarily numerous) are held on disk.  This means that the former
	   (and also public keys read from a private-key keyring) are found with 
	   a quick in-memory search while the latter require a scan of the 
	   keyring on disk */
	if( itemType == KEYMGMT_ITEM_PRIVATEKEY || \
		keysetInfo->subType == KEYSET_SUBTYPE_PGP_PRIVATE )
		{
		/* Try and locate the appropriate object in the PGP collection */
		pgpInfo = findEntry( keysetInfo->keyData, keyIDtype, keyID, 
							 keyIDlength, flags, &keyInfo );
		if( pgpInfo == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		}
	else
		{
		CONST_INIT_STRUCT_4( KEY_MATCH_INFO keyMatchInfo, \
							 keyIDtype, keyID, keyIDlength, flags );

		CONST_SET_STRUCT( keyMatchInfo.keyIDtype = keyIDtype; \
						  keyMatchInfo.keyID = keyID; \
						  keyMatchInfo.keyIDlength = keyIDlength; \
						  keyMatchInfo.flags = flags );

		/* Try and find the required key in the file */
		sseek( &keysetInfo->keysetFile->stream, 0 );
		status = readKeyring( keysetInfo, &keyMatchInfo, &keyInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's just a check or label read, we're done */
	if( flags & ( KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_LABEL_ONLY ) )
		{
		if( flags & KEYMGMT_FLAG_LABEL_ONLY )
			{
			const int userIDsize = min( pgpInfo->userIDlen[ 0 ],
										CRYPT_MAX_TEXTSIZE );

			*auxInfoLength = userIDsize;
			if( auxInfo != NULL )
				memcpy( auxInfo, pgpInfo->userID[ 0 ], userIDsize );
			}

		return( CRYPT_OK );
		}

	/* Set up the key to decrypt the private-key fields if necessary */
	if( itemType == KEYMGMT_ITEM_PRIVATEKEY )
		{
		static const int cryptMode = CRYPT_MODE_CFB;

		/* If no password is supplied, let the caller know that they need a
		   password */
		if( auxInfo == NULL )
			return( CRYPT_ERROR_WRONGKEY );

		/* If the key is stored as plaintext, we can't do anything with it.  
		   This is just a safety check, we never get here anyway, see the 
		   comment in readSecretKeyDecryptionInfo() */
		if( keyInfo->cryptAlgo == CRYPT_ALGO_NONE )
			return( CRYPT_ERROR_WRONGKEY );

		/* Convert the user password into an encryption context */
		setMessageCreateObjectInfo( &createInfo, keyInfo->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE,
								  ( void * ) &cryptMode, CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) )
			status = pgpPasswordToKey( createInfo.cryptHandle, 
									   ( keyInfo->cryptAlgo == CRYPT_ALGO_AES && \
									     keyInfo->aesKeySize > 0 ) ? \
										keyInfo->aesKeySize : CRYPT_UNUSED,
									   auxInfo, *auxInfoLength, 
									   keyInfo->hashAlgo, keyInfo->saltSize ? \
										keyInfo->salt : NULL,
									   keyInfo->keySetupIterations );
		if( cryptStatusOK( status ) )
			{
			int ivSize;

			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_GETATTRIBUTE, &ivSize, 
									  CRYPT_CTXINFO_IVSIZE );
			if( cryptStatusOK( status ) )
				{
				setMessageData( &msgData, keyInfo->iv, ivSize );
				status = krnlSendMessage( createInfo.cryptHandle,
										  IMESSAGE_SETATTRIBUTE_S, &msgData, 
										  CRYPT_CTXINFO_IV );
				}
			}
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		iSessionKey = createInfo.cryptHandle;
		}

	/* Load the key into the encryption context */
	setMessageCreateObjectInfo( &createInfo, keyInfo->pkcAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		{
		if( itemType == KEYMGMT_ITEM_PRIVATEKEY )
			krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	if( itemType == KEYMGMT_ITEM_PRIVATEKEY )
		{
		setMessageData( &msgData, pgpInfo->userID[ 0 ],
						pgpInfo->userIDlen[ 0 ] );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_LABEL );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, keyInfo->openPGPkeyID, PGP_KEYID_SIZE );
		krnlSendMessage( createInfo.cryptHandle,
						 IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, keyInfo->pubKeyData,
						keyInfo->pubKeyDataLen );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  ( itemType == KEYMGMT_ITEM_PRIVATEKEY ) ? \
									CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL : \
									CRYPT_IATTRIBUTE_KEY_PGP );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptHandle = createInfo.cryptHandle;

	/* If it's a public key, we're done */
	if( itemType != KEYMGMT_ITEM_PRIVATEKEY )
		return( CRYPT_OK );

	/* Import the encrypted key into the PKC context */
	setMechanismWrapInfo( &mechanismInfo, keyInfo->privKeyData,
						  keyInfo->privKeyDataLen, NULL, 0, *iCryptHandle,
						  iSessionKey, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT, 
							  &mechanismInfo, pgpInfo->isOpenPGP ? \
								MECHANISM_PRIVATEKEYWRAP_OPENPGP : \
								MECHANISM_PRIVATEKEYWRAP_PGP );
	clearMechanismInfo( &mechanismInfo );
	krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/****************************************************************************
*																			*
*									Write a Key								*
*																			*
****************************************************************************/

/* Add an item to the PGP keyring */

static int setItemFunction( KEYSET_INFO *keysetInfo,
							const CRYPT_HANDLE cryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const char *password, const int passwordLength,
							const int flags )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	PGP_INFO *pgpInfoPtr;
	RESOURCE_DATA msgData;
	BYTE iD[ CRYPT_MAX_HASHSIZE ];
	BOOLEAN contextPresent;
	char label[ CRYPT_MAX_TEXTSIZE + 1 ];
	int iDsize, i, status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );

	/* Check the object and extract ID information from it */
	status = krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_PKC );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
								  &cryptAlgo, CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) && cryptAlgo != CRYPT_ALGO_RSA )
			/* For now we can only store RSA keys because of the peculiar
			   properties of PGP DLP keys, which are actually two keys
			   with entirely different semantics and attributes but are
			   nevertheless occasionally treated as a single key by PGP */
			status = CRYPT_ARGERROR_NUM1;
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, iD, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		iDsize = msgData.length;
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	contextPresent = cryptStatusOK( krnlSendMessage( cryptHandle,
								IMESSAGE_CHECK, NULL,
								MESSAGE_CHECK_PKC_PRIVATE ) ) ? TRUE : FALSE;

	/* Find out where we can add data and what needs to be added.  At the 
	   moment we only allow atomic adds since the semantics of PGPs dual keys,
	   with assorted optional attributes attached to one or both keys, can't
	   easily be handled using a straightforward add */
	pgpInfoPtr = findEntry( keysetInfo->keyData, CRYPT_IKEYID_KEYID, iD, 
							iDsize, KEYMGMT_FLAG_NONE, NULL );
	if( pgpInfoPtr != NULL )
		return( CRYPT_ERROR_DUPLICATE );

	/* Make sure that the label of what we're adding doesn't duplicate the 
	   label of an existing object */
	setMessageData( &msgData, label, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		return( status );
	if( findEntry( keysetInfo->keyData, CRYPT_KEYID_NAME, msgData.data, 
				   msgData.length, KEYMGMT_FLAG_NONE, NULL ) != NULL )
		return( CRYPT_ERROR_DUPLICATE );

	/* Find out where we can add the new key data */
	pgpInfoPtr = keysetInfo->keyData;
	for( i = 0; i < MAX_PGP_OBJECTS; i++ )
		if( pgpInfoPtr[ i ].keyData == NULL )
				break;
	if( i == MAX_PGP_OBJECTS )
		return( CRYPT_ERROR_OVERFLOW );
	pgpInfoPtr = &pgpInfoPtr[ i ];

	/* If we're adding a private key, make sure that there's a password 
	   present.  Conversely, if there's a password present make sure that 
	   we're adding a private key */
	if( contextPresent )
		{
		/* We're adding a cert, there can't be a password present */
		if( password != NULL )
			return( CRYPT_ARGERROR_NUM1 );
		}
	else
		/* We're adding a private key, there must be a password present */
		if( password == NULL )
			return( CRYPT_ARGERROR_STR1 );

	/* We're ready to go, lock the object for our exclusive use */
	status = krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );

	/* Not implemented yet */
	status = CRYPT_ERROR_NOTAVAIL;

	krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_FALSE, 
					 CRYPT_IATTRIBUTE_LOCKED );

	return( status );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Shutdown functions */

static void shutdownFunction( KEYSET_INFO *keysetInfo )
	{
	if( keysetInfo->keyData != NULL )
		{
		PGP_INFO *pgpInfo = ( PGP_INFO * ) keysetInfo->keyData;

		if( keysetInfo->subType == KEYSET_SUBTYPE_PGP_PRIVATE )
			{
			int i;

			for( i = 0; i < MAX_PGP_OBJECTS; i++ )
				pgpFreeEntry( &pgpInfo[ i ] );
			}
		else
			pgpFreeEntry( pgpInfo );
		clFree( "shutdownFunction", pgpInfo );
		keysetInfo->keyData = NULL;
		keysetInfo->keyDataSize = 0;
		}
	}

/* PGP public keyrings can be arbitrarily large so we don't try to do any
   preprocessing, all we do at this point is allocate the key info */

static int initPublicFunction( KEYSET_INFO *keysetInfo, const char *name,
							   const CRYPT_KEYOPT_TYPE options )
	{
	PGP_INFO *pgpInfo;

	assert( name == NULL );

	/* Allocate memory for the key info */
	if( ( pgpInfo = clAlloc( "initPublicFunction", \
							 sizeof( PGP_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( pgpInfo, 0, sizeof( PGP_INFO ) );
	if( ( pgpInfo->keyData = clAlloc( "initPublicFunction", \
									  KEYRING_BUFSIZE ) ) == NULL )
		{
		clFree( "initPublicFunction", pgpInfo );
		return( CRYPT_ERROR_MEMORY );
		}
	pgpInfo->keyDataLen = KEYRING_BUFSIZE;
	keysetInfo->keyData = pgpInfo;
	keysetInfo->keyDataSize = sizeof( PGP_INFO );

	return( CRYPT_OK );
	}

/* A PGP private keyring can contain multiple keys and whatnot, so when we
   open it we scan it and record various pieces of information about it
   that we can use later when we need to access it */

static int initPrivateFunction( KEYSET_INFO *keysetInfo, const char *name,
								const CRYPT_KEYOPT_TYPE options )
	{
	PGP_INFO *pgpInfo;

	assert( name == NULL );

	/* Allocate the PGP object info */
	if( ( pgpInfo = clAlloc( "initPrivateFunction", \
							 sizeof( PGP_INFO ) * MAX_PGP_OBJECTS ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( pgpInfo, 0, sizeof( PGP_INFO ) * MAX_PGP_OBJECTS );
	keysetInfo->keyData = pgpInfo;
	keysetInfo->keyDataSize = sizeof( PGP_INFO ) * MAX_PGP_OBJECTS;

	/* If this is a newly-created keyset, there's nothing left to do */
	if( options == CRYPT_KEYOPT_CREATE )
		return( CRYPT_OK );

	/* Read all of the keys in the keyring */
	return( readKeyring( keysetInfo, NULL, NULL ) );
	}

/****************************************************************************
*																			*
*							Keyset Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodPGPPublic( KEYSET_INFO *keysetInfo )
	{
	/* Set the access method pointers */
	keysetInfo->initFunction = initPublicFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->setItemFunction = setItemFunction;

	return( CRYPT_OK );
	}

int setAccessMethodPGPPrivate( KEYSET_INFO *keysetInfo )
	{
	/* Set the access method pointers */
	keysetInfo->initFunction = initPrivateFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->setItemFunction = setItemFunction;

	return( CRYPT_OK );
	}
#endif /* USE_PGPKEYS */
