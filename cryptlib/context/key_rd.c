/****************************************************************************
*																			*
*						Public/Private Key Read Routines					*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#include <stdio.h>
#define PKC_CONTEXT		/* Indicate that we're working with PKC context */
#if defined( INC_ALL )
  #include "context.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "context/context.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/* Although there is a fair amount of commonality between public and private-
   key functions, we keep them distinct to enforce red/black separation.

   The DLP algorithms split the key components over the information in the
   AlgorithmIdentifier and the actual public/private key components, with the
   (p, q, g) set classed as domain parameters and included in the
   AlgorithmIdentifier and y being the actual key.

	params = SEQ {
		p INTEGER,
		q INTEGER,				-- q for DSA
		g INTEGER,				-- g for DSA
		j INTEGER OPTIONAL,		-- X9.42 only
		validationParams [...]	-- X9.42 only
		}

	key = y INTEGER				-- g^x mod p

   For peculiar historical reasons (copying errors and the use of obsolete
   drafts as reference material) the X9.42 interpretation used in PKIX 
   reverses the second two parameters from FIPS 186 (so it uses p, g, q 
   instead of p, q, g), so when we read/write the parameter information we 
   have to switch the order in which we read the values if the algorithm 
   isn't DSA */

#define hasReversedParams( cryptAlgo ) \
		( ( cryptAlgo ) == CRYPT_ALGO_DH || \
		  ( cryptAlgo ) == CRYPT_ALGO_ELGAMAL )

#ifdef USE_PKC

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Generate a key ID, which is the SHA-1 hash of the SubjectPublicKeyInfo.
   There are about half a dozen incompatible ways of generating X.509
   keyIdentifiers, the following is conformant with the PKIX specification
   ("use whatever you like as long as it's unique"), but differs slightly
   from one common method that hashes the SubjectPublicKey without the
   BIT STRING encapsulation.  The problem with this is that some DLP-based 
   algorithms use a single integer as the SubjectPublicKey, leading to
   potential key ID clashes */

static void calculateFlatKeyID( const void *keyInfo, const int keyInfoSize,
								BYTE *keyID, const int keyIdMaxLen )
	{
	HASHFUNCTION hashFunction;

	assert( isReadPtr( keyInfo, keyInfoSize ) );
	assert( isWritePtr( keyID, CRYPT_MAX_HASHSIZE ) );

	/* Hash the key info to get the key ID */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
	hashFunction( NULL, keyID, keyIdMaxLen, ( BYTE * ) keyInfo, keyInfoSize, 
				  HASH_ALL );
	}

static int calculateKeyID( CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *publicKey = contextInfoPtr->ctxPKC;
	STREAM stream;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 4 ) + 50 + 8 ];
	const CRYPT_ALGO_TYPE cryptAlgo = contextInfoPtr->capabilityInfo->cryptAlgo;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC );
	assert( publicKey->writePublicKeyFunction != NULL );

	/* If the public key info is present in pre-encoded form, calculate the
	   key ID directly from that */
	if( publicKey->publicKeyInfo != NULL )
		{
		int length;

		calculateFlatKeyID( publicKey->publicKeyInfo, 
							publicKey->publicKeyInfoSize, 
							publicKey->keyID, KEYID_SIZE );
		if( cryptAlgo != CRYPT_ALGO_KEA && cryptAlgo != CRYPT_ALGO_RSA )
			return( CRYPT_OK );

		/* If it's an RSA context, we also need to remember the PGP key ID 
		   alongside the cryptlib one */
		if( cryptAlgo == CRYPT_ALGO_RSA )
			{
			sMemConnect( &stream, publicKey->publicKeyInfo,
						 publicKey->publicKeyInfoSize );
			readSequence( &stream, NULL );
			readUniversal( &stream );
			readBitStringHole( &stream, &length, 
							   bitsToBytes( MIN_PKCSIZE_BITS ), DEFAULT_TAG );
			readSequence( &stream, NULL );
			readInteger( &stream, buffer, &length, CRYPT_MAX_PKCSIZE );
			assert( readInteger( &stream, NULL, NULL, \
								 CRYPT_MAX_PKCSIZE ) == CRYPT_OK );
			sMemDisconnect( &stream );

			if( length > PGP_KEYID_SIZE )
				memcpy( publicKey->pgpKeyID, 
						buffer + length - PGP_KEYID_SIZE, PGP_KEYID_SIZE );
			return( CRYPT_OK );
			}

#ifdef USE_KEA
		/* If it's a KEA context, we also need to remember the start and
		   length of the domain parameters and key agreement public value in
		   the encoded key data */
		sMemConnect( &stream, publicKey->publicKeyInfo,
					 publicKey->publicKeyInfoSize );
		readSequence( &stream, NULL );
		readSequence( &stream, NULL );
		readUniversal( &stream );
		readOctetStringHole( &stream, &length, 
							 bitsToBytes( MIN_PKCSIZE_BITS ), DEFAULT_TAG );
		publicKey->domainParamPtr = sMemBufPtr( &stream );
		publicKey->domainParamSize = ( int ) length;
		sSkip( &stream, length );
		readBitStringHole( &stream, &length, bitsToBytes( MIN_PKCSIZE_BITS ), 
						   DEFAULT_TAG );
		publicKey->publicValuePtr = sMemBufPtr( &stream );
		publicKey->publicValueSize = ( int ) length - 1;
		assert( sSkip( &stream, length ) == CRYPT_OK );
		sMemDisconnect( &stream );
#endif /* USE_KEA */

		return( CRYPT_OK );
		}

	/* Write the public key fields to a buffer and hash them to get the key
	   ID */
	sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 4 ) + 50 );
	status = publicKey->writePublicKeyFunction( &stream, contextInfoPtr, 
												KEYFORMAT_CERT, "public" );
	calculateFlatKeyID( buffer, stell( &stream ), 
						publicKey->keyID, KEYID_SIZE );
	sMemClose( &stream );

	/* If it's an RSA key, we need to calculate the PGP key ID alongside the
	   cryptlib one */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		const PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
		const int length = BN_bn2bin( &pkcInfo->rsaParam_n, buffer );

		if( length > PGP_KEYID_SIZE )
			memcpy( publicKey->pgpKeyID, 
					buffer + length - PGP_KEYID_SIZE, PGP_KEYID_SIZE );
		}

	/* If the OpenPGP ID is already set (from the key being loaded from a PGP
	   keyset), we're done */
	if( publicKey->openPgpKeyIDSet )
		return( status );

	/* Finally, set the OpenPGP key ID if it's a PGP algorithm type.  Since 
	   calculation of the OpenPGP ID requires the presence of data that 
	   isn't usually present in a non-PGP key, we can't calculate a real 
	   OpenPGP ID for some keys but have to use the next-best thing, the 
	   first 64 bits of the key ID.  This shouldn't be a major problem 
	   because it's really only going to be used with private keys, public 
	   keys will be in PGP format and selected by user ID (for encryption) 
	   or PGP ID/genuine OpenPGP ID (signing) */
	if( ( cryptAlgo == CRYPT_ALGO_RSA || cryptAlgo == CRYPT_ALGO_DSA || \
		  cryptAlgo == CRYPT_ALGO_ELGAMAL ) && \
		publicKey->pgpCreationTime > MIN_TIME_VALUE )
		{
		HASHFUNCTION hashFunction;
		HASHINFO hashInfo;
		BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ], packetHeader[ 64 + 8 ];
		int hashSize, length;

		/* There's a creation time present, generate a real OpenPGP key ID:
			byte		ctb = 0x99
			byte[2]		length
			-- Key data --
			byte		version = 4
			byte[4]		key generation time 
			byte		algorithm
			byte[]		key data
		  We do this by writing the public key fields to a buffer and 
		  creating a separate PGP public key header, then hashing the two */
		sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 4 ) + 50 );
		status = publicKey->writePublicKeyFunction( &stream, contextInfoPtr, 
													KEYFORMAT_PGP, "public" );
		length = stell( &stream );
		packetHeader[ 0 ] = 0x99;
		packetHeader[ 1 ] = ( length >> 8 ) & 0xFF;
		packetHeader[ 2 ] = length & 0xFF;

		/* Hash the data needed to generate the OpenPGP keyID */
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
		hashFunction( hashInfo, NULL, 0, packetHeader, 1 + 2, HASH_START );
		hashFunction( hashInfo, hash, CRYPT_MAX_HASHSIZE, buffer, length, 
					  HASH_END );
		memcpy( publicKey->openPgpKeyID, 
				hash + hashSize - PGP_KEYID_SIZE, PGP_KEYID_SIZE );
		sMemClose( &stream );
		}
	else
		/* No creation time or non-PGP algorithm, fake it */
		memcpy( publicKey->openPgpKeyID, publicKey->keyID,
				PGP_KEYID_SIZE );
	publicKey->openPgpKeyIDSet = TRUE;

	return( status );
	}

/****************************************************************************
*																			*
*								Read Public Keys							*
*																			*
****************************************************************************/

/* Read X.509 SubjectPublicKeyInfo public keys */

static int readRsaSubjectPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
									int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	/* Read the SubjectPublicKeyInfo header field and parameter data if
	   there's any present.  We read the outer wrapper in generic form since
	   it may be context-specific-tagged if it's coming from a keyset (RSA
	   public keys is the one place where PKCS #15 keys differ from X.509
	   ones) or something odd from CRMF */
	readGenericHole( stream, NULL, 8 + bitsToBytes( MIN_PKCSIZE_BITS ), 
					 DEFAULT_TAG );
	status = readAlgoID( stream, NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Set the maximum permitted actions.  More restrictive permissions may 
	   be set by higher-level code if required.  In particular if the key is
	   a pure public key (rather than merely the public portions of a 
	   private key), the actions will be restricted at that point to encrypt 
	   and sig-check only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL );

	/* Read the BITSTRING encapsulation and the public key fields */
	readBitStringHole( stream, NULL, bitsToBytes( MIN_PKCSIZE_BITS ), 
					   DEFAULT_TAG );
	readSequence( stream, NULL );
	status = readBignum( stream, &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_e );
	return( status );
	}

static int readDlpSubjectPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
									int *actionFlags )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	CRYPT_ALGO_TYPE cryptAlgo;
	int extraLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	/* Read the SubjectPublicKeyInfo header field and parameter data if
	   there's any present */
	readGenericHole( stream, NULL, \
					 8 + ( bitsToBytes( MIN_PKCSIZE_BITS ) + \
						   bitsToBytes( MIN_PKCSIZE_BITS ) ), DEFAULT_TAG );
	status = readAlgoIDex( stream, &cryptAlgo, NULL, &extraLength );
	if( cryptStatusOK( status ) && extraLength > 0 )
		{
		assert( contextInfoPtr->capabilityInfo->cryptAlgo == cryptAlgo );

		/* Read the header and key parameters */
		readSequence( stream, NULL );
		readBignum( stream, &dlpKey->dlpParam_p );
		if( hasReversedParams( cryptAlgo ) )
			{
			status = readBignum( stream, &dlpKey->dlpParam_g );
			if( cryptStatusOK( status ) )
				status = readBignum( stream, &dlpKey->dlpParam_q );
			}
		else
			{
			status = readBignum( stream, &dlpKey->dlpParam_q );
			if( cryptStatusOK( status ) )
				status = readBignum( stream, &dlpKey->dlpParam_g );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for DLP algorithms, we make the usage 
	   internal-only.  If the key is a pure public key (rather than merely 
	   the public portions of a  private key), the actions will be 
	   restricted by higher-level code to sig-check only */
	if( cryptAlgo == CRYPT_ALGO_DSA )
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
									   ACTION_PERM_NONE_EXTERNAL );
	else
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );

	/* Read the BITSTRING encapsulation and the public key fields */
	readBitStringHole( stream, NULL, bitsToBytes( MIN_PKCSIZE_BITS ), 
					   DEFAULT_TAG );
	return( readBignum( stream, &dlpKey->dlpParam_y ) );
	}

#ifdef USE_SSH1

/* Read SSHv1 public keys:

	uint32		keysize_bits
	mpint		exponent
	mpint		modulus */

int readSsh1RsaPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
						  int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	const int length = readUint32( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	/* Make sure that the nominal keysize value is valid */
	if( length < MIN_PKCSIZE_BITS || \
		length > bytesToBits( CRYPT_MAX_PKCSIZE ) )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  SSH keys are only used internally,
	   so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSH public key information */
	status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_e, 2, 256 );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_n,
										   MIN_PKCSIZE_BITS, 
										   bytesToBits( CRYPT_MAX_PKCSIZE ) );
	return( status );
	}
#endif /* USE_SSH1 */

#ifdef USE_SSH

/* Read SSHv2 public keys:

	string	certificate
		string	"ssh-rsa"	"ssh-dss"
		mpint	e			p
		mpint	n			q
		mpint				g
		mpint				y */

int readSshRsaPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
						 int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	char buffer[ 16 + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	/* Read the wrapper and make sure that it's OK */
	readUint32( stream );
	status = readString32( stream, buffer, &length, 7 );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 7 || memcmp( buffer, "ssh-rsa", 7 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  SSH keys are only used internally,
	   so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSH public key information */
	status = readBignumInteger32( stream, &rsaKey->rsaParam_e, 1, 16 );
	if( cryptStatusOK( status ) )
		status = readBignumInteger32( stream, &rsaKey->rsaParam_n,
									  bitsToBytes( MIN_PKCSIZE_BITS ), 
									  CRYPT_MAX_PKCSIZE );
	return( status );
	}

int readSshDlpPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
						 int *actionFlags )
	{
	PKC_INFO *dsaKey = contextInfoPtr->ctxPKC;
	const BOOLEAN isDH = \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH );
	char buffer[ 16 + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	/* Read the wrapper and make sure that it's OK.  SSHv2 uses PKCS #3 
	   rather than X9.42-style DH keys, so we have to treat this algorithm 
	   type specially */
	readUint32( stream );
	if( isDH )
		{
		status = readString32( stream, buffer, &length, 6 );
		if( cryptStatusError( status ) )
			return( status );
		if( length != 6 || memcmp( buffer, "ssh-dh", 6 ) )
			return( CRYPT_ERROR_BADDATA );

		/* Set the maximum permitted actions.  SSH keys are only used 
		   internally, so we restrict the usage to internal-only.  Since DH 
		   keys can be both public and private keys, we allow both usage 
		   types even though technically it's a public key */
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );

		/* Read the SSH public key information.  Since SSH uses PKCS #3 DH 
		   values we can end up with very small values for g, so we have to
		   handle this specially */
		status = readBignumInteger32( stream, &dsaKey->dlpParam_p,
									  bitsToBytes( MIN_PKCSIZE_BITS ), 
									  CRYPT_MAX_PKCSIZE );
		if( cryptStatusOK( status ) )
			status = readBignumInteger32( stream, &dsaKey->dlpParam_g,
										  1, CRYPT_MAX_PKCSIZE );
		return( status );
		}

	/* It's a standard DLP key, read the wrapper and make sure that it's 
	   OK */
	status = readString32( stream, buffer, &length, 7 );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 7 || memcmp( buffer, "ssh-dss", 7 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  SSH keys are only used internally,
	   so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSH public key information */
	status = readBignumInteger32( stream, &dsaKey->dlpParam_p,
								  bitsToBytes( MIN_PKCSIZE_BITS ), 
								  CRYPT_MAX_PKCSIZE );
	if( cryptStatusOK( status ) )
		status = readBignumInteger32( stream, &dsaKey->dlpParam_q,
									  bitsToBytes( 128 ), 
									  CRYPT_MAX_PKCSIZE );
	if( cryptStatusOK( status ) )
		status = readBignumInteger32( stream, &dsaKey->dlpParam_g,
									  bitsToBytes( MIN_PKCSIZE_BITS ), 
									  CRYPT_MAX_PKCSIZE );
	if( cryptStatusOK( status ) && !isDH )
		status = readBignumInteger32( stream, &dsaKey->dlpParam_y,
									  bitsToBytes( 128 ), 
									  CRYPT_MAX_PKCSIZE );
	return( status );
	}
#endif /* USE_SSH */

#ifdef USE_SSL

/* Read SSL public keys:

	uint16		dh_pLen
	byte[]		dh_p
	uint16		dh_gLen
	byte[]		dh_g
  [	uint16		dh_YsLen ]
  [	byte[]		dh_Ys	 ]

   The DH y value is nominally attached to the DH p and g values, but 
   isn't processed at this level since this is a pure PKCS #3 DH key
   and not a generic DLP key */

int readSslDlpPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
						 int *actionFlags )
	{
	PKC_INFO *dhKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	/* Set the maximum permitted actions.  SSL keys are only used 
	   internally, so we restrict the usage to internal-only.  Since DH 
	   keys can be both public and private keys, we allow both usage 
	   types even though technically it's a public key */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
								   ACTION_PERM_NONE_EXTERNAL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSL public key information.  Since SSL uses PKCS #3 DH 
	   values we can end up with very small values for g, so we have to
	   handle this specially */
	status = readBignumInteger16U( stream, &dhKey->dlpParam_p,
								   bitsToBytes( MIN_PKCSIZE_BITS ), 
								   CRYPT_MAX_PKCSIZE );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16U( stream, &dhKey->dlpParam_g, 1, 
									   CRYPT_MAX_PKCSIZE );
	return( status );
	}
#endif /* USE_SSL */

#ifdef USE_PGP 

/* Read PGP public keys:

	byte		version
	uint32		creationTime
	[ uint16	validity - version 2 or 3 only ]
	byte		RSA		DSA		Elgamal
	mpi			n		p		p
	mpi			e		q		g
	mpi					g		y
	mpi					y */

int readPgpRsaPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
						 int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	time_t creationTime;
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	/* Read the header info */
	value = sgetc( stream );
	if( value != PGP_VERSION_2 && value != PGP_VERSION_3 && \
		value != PGP_VERSION_OPENPGP )
		return( CRYPT_ERROR_BADDATA );
	status = readUint32Time( stream, &creationTime );
	if( cryptStatusError( status ) )
		return( status );
	rsaKey->pgpCreationTime = creationTime;
	if( value == PGP_VERSION_2 || value == PGP_VERSION_3 )
		/* Skip validity period */
		sSkip( stream, 2 );

	/* Set the maximum permitted actions.  If there are no restrictions we
	   allow external usage, if the keys are encryption-only or sig-only we
	   make the usage internal-only because of RSA's signature/encryption
	   duality.  If the key is a pure public key (rather than merely the 
	   public portions of a  private key), the actions will be restricted by 
	   higher-level code to sig-check only  */
	value = sgetc( stream );
	if( value != PGP_ALGO_RSA && value != PGP_ALGO_RSA_ENCRYPT && \
		value != PGP_ALGO_RSA_SIGN )
		return( CRYPT_ERROR_BADDATA );
	*actionFlags = 0;
	if( value != PGP_ALGO_RSA_SIGN )
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
	if( value != PGP_ALGO_RSA_ENCRYPT )
		*actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL ) | \
						MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
	if( value != PGP_ALGO_RSA )
		*actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( *actionFlags );

	/* Read the PGP public key information */
	status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_n, 
									   MIN_PKCSIZE_BITS, 
									   bytesToBits( PGP_MAX_MPISIZE ) );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_e, 2, 
										   bytesToBits( PGP_MAX_MPISIZE ) );
	return( status );
	}

int readPgpDlpPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
						 int *actionFlags )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	time_t creationTime;
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	/* Read the header info */
	value = sgetc( stream );
	if( value != PGP_VERSION_OPENPGP )
		return( CRYPT_ERROR_BADDATA );
	status = readUint32Time( stream, &creationTime );
	if( cryptStatusError( status ) )
		return( status );
	dlpKey->pgpCreationTime = creationTime;

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for DLP algorithms, we make the usage 
	   internal-only.  If the key is a pure public key (rather than merely 
	   the public portions of a  private key), the actions will be 
	   restricted by higher-level code to sig-check only  */
	value = sgetc( stream );
	if( value != PGP_ALGO_DSA && value != PGP_ALGO_ELGAMAL )
		return( CRYPT_ERROR_BADDATA );
	if( value == PGP_ALGO_DSA )
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
									   ACTION_PERM_NONE_EXTERNAL );
	else
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );

	/* Read the PGP public key information */
	status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_p, 
									   MIN_PKCSIZE_BITS, 
									   bytesToBits( PGP_MAX_MPISIZE ) );
	if( cryptStatusOK( status ) && value == PGP_ALGO_DSA )
		status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_q, 155, 
										   bytesToBits( PGP_MAX_MPISIZE ) );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_g, 2, 
										   bytesToBits( PGP_MAX_MPISIZE ) );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_y, 
										   MIN_PKCSIZE_BITS, 
										   bytesToBits( PGP_MAX_MPISIZE ) );
	return( status );
	}
#endif /* USE_PGP */

/* Umbrella public-key read functions */

static int readPublicKeyRsaFunction( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
									 const KEYFORMAT_TYPE formatType )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );
	assert( formatType == KEYFORMAT_CERT || formatType == KEYFORMAT_SSH || \
			formatType == KEYFORMAT_SSH1 || formatType == KEYFORMAT_PGP );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			status = readRsaSubjectPublicKey( stream, contextInfoPtr, 
											  &actionFlags );
			break;

#ifdef USE_SSH1
		case KEYFORMAT_SSH1:
			status = readSsh1RsaPublicKey( stream, contextInfoPtr, 
										   &actionFlags );
			break;
#endif /* USE_SSH1 */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			status = readSshRsaPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_SSH */

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			status = readPgpRsaPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_PGP */

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}
	if( cryptStatusError( status ) )
		return( status );
	return( krnlSendMessage( contextInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE, &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

static int readPublicKeyDlpFunction( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
									 const KEYFORMAT_TYPE formatType )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	assert( formatType == KEYFORMAT_CERT || formatType == KEYFORMAT_SSH || \
			formatType == KEYFORMAT_SSL || formatType == KEYFORMAT_PGP );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			status = readDlpSubjectPublicKey( stream, contextInfoPtr, 
											  &actionFlags );
			break;

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			status = readSshDlpPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_SSH */

#ifdef USE_SSL
		case KEYFORMAT_SSL:
			status = readSslDlpPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_SSL */
		
#ifdef USE_PGP
		case KEYFORMAT_PGP:
			status = readPgpDlpPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_PGP */

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}
	if( cryptStatusError( status ) )
		return( status );
	return( krnlSendMessage( contextInfoPtr->objectHandle,
							 IMESSAGE_SETATTRIBUTE, &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

/****************************************************************************
*																			*
*								Read Private Keys							*
*																			*
****************************************************************************/

/* Read private key components.  This function assumes that the public
   portion of the context has already been set up */

static int readRsaPrivateKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Read the header and key components */
	status = readSequence( stream, NULL );
	if( peekTag( stream ) == MAKE_CTAG( 0 ) )
		/* Erroneously written in older code */
		readConstructed( stream, NULL, 0 );
	if( cryptStatusOK( status ) && \
		peekTag( stream ) == MAKE_CTAG_PRIMITIVE( 0 ) )
		{
		/* The public components may already have been read when we read a
		   corresponding public key or certificate, so we only read them if
		   they're not already present */
		if( BN_is_zero( &rsaKey->rsaParam_n ) )
			status = readBignumTag( stream, &rsaKey->rsaParam_n, 0 );
		else
			status = readUniversal( stream );
		if( cryptStatusOK( status ) )
			{
			if( BN_is_zero( &rsaKey->rsaParam_e ) )
				status = readBignumTag( stream, &rsaKey->rsaParam_e, 1 );
			else
				status = readUniversal( stream );
			}
		}
	else
		{
		assert( !BN_is_zero( &rsaKey->rsaParam_n ) );
		assert( !BN_is_zero( &rsaKey->rsaParam_e ) );
		}
	if( cryptStatusOK( status ) && \
		peekTag( stream ) == MAKE_CTAG_PRIMITIVE( 2 ) )
		status = readBignumTag( stream, &rsaKey->rsaParam_d, 2 );
	if( cryptStatusOK( status ) )
		status = readBignumTag( stream, &rsaKey->rsaParam_p, 3 );
	if( cryptStatusOK( status ) )
		status = readBignumTag( stream, &rsaKey->rsaParam_q, 4 );
	if( cryptStatusOK( status ) && \
		peekTag( stream ) == MAKE_CTAG_PRIMITIVE( 5 ) )
		{
		status = readBignumTag( stream, &rsaKey->rsaParam_exponent1, 5 );
		if( cryptStatusOK( status ) )
			status = readBignumTag( stream, &rsaKey->rsaParam_exponent2, 6 );
		if( cryptStatusOK( status ) )
			status = readBignumTag( stream, &rsaKey->rsaParam_u, 7 );
		}
	return( status );
	}

static int readRsaPrivateKeyOld( STREAM *stream, CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Read the header and key components */
	readOctetStringHole( stream, NULL, 
						 ( 4 * bitsToBytes( MIN_PKCSIZE_BITS ) ), 
						 DEFAULT_TAG );
	readSequence( stream, NULL );
	readShortInteger( stream, NULL );
	status = readBignum( stream, &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_e );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_d );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_p );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_q );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_exponent1 );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_exponent2 );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_u );
	return( status );
	}

static int readDlpPrivateKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );

	/* Read the header and key components */
	if( peekTag( stream ) == BER_SEQUENCE )
		{
		/* Erroneously written in older code */
		readSequence( stream, NULL );
		return( readBignumTag( stream, &dlpKey->dlpParam_x, 0 ) );
		}
	return( readBignum( stream, &dlpKey->dlpParam_x ) );
	}

/* Read PGP private key components.  This function assumes that the public
   portion of the context has already been set up */

static int readPgpRsaPrivateKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Read the PGP private key information */
	status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_d, 
									   MIN_PKCSIZE_BITS, 
									   bytesToBits( PGP_MAX_MPISIZE ) );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_p, 
										   MIN_PKCSIZE_BITS / 2, 
										   bytesToBits( PGP_MAX_MPISIZE ) );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_q, 
										   MIN_PKCSIZE_BITS / 2, 
										   bytesToBits( PGP_MAX_MPISIZE ) );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_u, 
										   MIN_PKCSIZE_BITS / 2, 
										   bytesToBits( PGP_MAX_MPISIZE ) );
	return( status );
	}

static int readPgpDlpPrivateKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );

	/* Read the PGP private key information */
	return( readBignumInteger16Ubits( stream, &dlpKey->dlpParam_x, 155, 
									  bytesToBits( PGP_MAX_MPISIZE ) ) );
	}

/* Umbrella private-key read functions */

static int readPrivateKeyRsaFunction( STREAM *stream, 
									  CONTEXT_INFO *contextInfoPtr,
									  const KEYFORMAT_TYPE formatType )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );
	assert( formatType == KEYFORMAT_PRIVATE || \
			formatType == KEYFORMAT_PRIVATE_OLD || \
			formatType == KEYFORMAT_PGP );

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( readRsaPrivateKey( stream, contextInfoPtr ) );

		case KEYFORMAT_PRIVATE_OLD:
			return( readRsaPrivateKeyOld( stream, contextInfoPtr ) );

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			return( readPgpRsaPrivateKey( stream, contextInfoPtr ) );
#endif /* USE_PGP */
		}

	retIntError();
	}

static int readPrivateKeyDlpFunction( STREAM *stream, 
									  CONTEXT_INFO *contextInfoPtr,
									  const KEYFORMAT_TYPE formatType )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC && \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	assert( formatType == KEYFORMAT_PRIVATE || \
			formatType == KEYFORMAT_PGP );

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( readDlpPrivateKey( stream, contextInfoPtr ) );

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			return( readPgpDlpPrivateKey( stream, contextInfoPtr ) );
#endif /* USE_PGP */
		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Read DL Values								*
*																			*
****************************************************************************/

/* Unlike the simpler RSA PKC, DL-based PKCs produce a pair of values that
   need to be encoded as structured data.  The following two functions 
   perform this en/decoding.  SSH assumes that DLP values are two fixed-size
   blocks of 20 bytes, so we can't use the normal read/write routines to 
   handle these values */

static int decodeDLValuesFunction( const BYTE *buffer, const int bufSize, 
								   BIGNUM **value1, BIGNUM **value2, 
								   const CRYPT_FORMAT_TYPE formatType )
	{
	STREAM stream;
	int status;

	assert( isReadPtr( buffer, bufSize ) );
	assert( isWritePtr( value1, sizeof( BIGNUM * ) ) );
	assert( isWritePtr( value2, sizeof( BIGNUM * ) ) );
	assert( formatType == CRYPT_FORMAT_CRYPTLIB || \
			formatType == CRYPT_FORMAT_PGP || \
			formatType == CRYPT_IFORMAT_SSH );

	sMemConnect( &stream, buffer, bufSize );

	/* Read the DL components from the buffer */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			readSequence( &stream, NULL );
			status = readBignum( &stream, *value1 );
			if( cryptStatusOK( status ) )
				status = readBignum( &stream, *value2 );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = readBignumInteger16Ubits( &stream, *value1, 160 - 24,
											   bytesToBits( PGP_MAX_MPISIZE ) );
			if( cryptStatusOK( status ) )
				status = readBignumInteger16Ubits( &stream, *value2, 160 - 24,
												   bytesToBits( PGP_MAX_MPISIZE ) );
			break;
#endif /* USE_PGP */
	
#ifdef USE_SSH
		case CRYPT_IFORMAT_SSH:
			status = CRYPT_OK;
			if( BN_bin2bn( buffer, 20, *value1 ) == NULL || \
				BN_bin2bn( buffer + 20, 20, *value2 ) == NULL )
				status = CRYPT_ERROR_MEMORY;
			break;
#endif /* USE_SSH */

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Clean up */
	sMemDisconnect( &stream );
	return( status );
	}

/****************************************************************************
*																			*
*							Context Access Routines							*
*																			*
****************************************************************************/

void initKeyRead( CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) && \
			contextInfoPtr->type == CONTEXT_PKC );

	/* Set the access method pointers */
	pkcInfo->calculateKeyIDFunction = calculateKeyID;
	if( isDlpAlgo( contextInfoPtr->capabilityInfo->cryptAlgo ) )
		{
		pkcInfo->readPublicKeyFunction = readPublicKeyDlpFunction;
		pkcInfo->readPrivateKeyFunction = readPrivateKeyDlpFunction;
		pkcInfo->decodeDLValuesFunction = decodeDLValuesFunction;
		}
	else
		{
		pkcInfo->readPublicKeyFunction = readPublicKeyRsaFunction;
		pkcInfo->readPrivateKeyFunction = readPrivateKeyRsaFunction;
		}
	}
#else

void initKeyRead( CONTEXT_INFO *contextInfoPtr )
	{
	}
#endif /* USE_PKC */
