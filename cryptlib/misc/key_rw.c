/****************************************************************************
*																			*
*					Public/Private Key Read/Write Routines					*
*					  Copyright Peter Gutmann 1992-2003						*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "pgp.h"
  #include "asn1_rw.h"
  #include "asn1s_rw.h"
  #include "context.h"
  #include "misc_rw.h"
#elif defined( INC_CHILD )
  #include "../envelope/pgp.h"
  #include "asn1_rw.h"
  #include "asn1s_rw.h"
  #include "context.h"
  #include "misc_rw.h"
#else
  #include "envelope/pgp.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
  #include "misc/context.h"
  #include "misc/misc_rw.h"
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

/* Define the following to enable legacy-mode compatibility with old versions
   of PKCS #15 (this is strongly discourage since it writes a format not
   compatible with the current form of the standard) */

/* #define OLD_MODE */

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
								BYTE *keyID )
	{
	HASHFUNCTION hashFunction;

	/* Hash the key info to get the key ID */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
	hashFunction( NULL, keyID, ( BYTE * ) keyInfo, keyInfoSize, HASH_ALL );
	}

int calculateKeyID( CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *publicKey = contextInfoPtr->ctxPKC;
	STREAM stream;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 4 ) + 50 ];
	const CRYPT_ALGO_TYPE cryptAlgo = contextInfoPtr->capabilityInfo->cryptAlgo;
	int status;

	assert( publicKey->writePublicKeyFunction != NULL );

	/* If the public key info is present in pre-encoded form, calculate the
	   key ID directly from that */
	if( publicKey->publicKeyInfo != NULL )
		{
		int length;

		calculateFlatKeyID( publicKey->publicKeyInfo, 
							publicKey->publicKeyInfoSize, publicKey->keyID );
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
			readBitStringHole( &stream, &length, DEFAULT_TAG );
			readSequence( &stream, NULL );
			readInteger( &stream, buffer, &length, CRYPT_MAX_PKCSIZE );
			assert( sGetStatus( &stream ) == CRYPT_OK );
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
		readOctetStringHole( &stream, &length, DEFAULT_TAG );
		publicKey->domainParamPtr = sMemBufPtr( &stream );
		publicKey->domainParamSize = ( int ) length;
		sSkip( &stream, length );
		readBitStringHole( &stream, &length, DEFAULT_TAG );
		publicKey->publicValuePtr = sMemBufPtr( &stream );
		publicKey->publicValueSize = ( int ) length - 1;
		assert( sGetStatus( &stream ) == CRYPT_OK );
		sMemDisconnect( &stream );
#endif /* USE_KEA */

		return( CRYPT_OK );
		}

	/* Write the public key fields to a buffer and hash them to get the key
	   ID */
	sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 4 ) + 50 );
	status = publicKey->writePublicKeyFunction( &stream, contextInfoPtr, 
												KEYFORMAT_CERT, "public" );
	calculateFlatKeyID( buffer, stell( &stream ), publicKey->keyID );
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

	/* Finally, set the OpenPGP key ID.  Since calculation of the OpenPGP ID 
	   requires the presence of data that isn't usually present in a non-
	   PGP key, we can't calculate a real OpenPGP ID for some keys but have 
	   to use the next-best thing, the first 64 bits of the key ID.  This 
	   shouldn't be a major problem because it's really only going to be 
	   used with private keys, public keys will be in PGP format and selected 
	   by user ID (for encryption) or PGP ID/genuine OpenPGP ID (signing) */
	if( publicKey->pgpCreationTime )
		{
		HASHFUNCTION hashFunction;
		HASHINFO hashInfo;
		BYTE hash[ CRYPT_MAX_HASHSIZE ], packetHeader[ 64 ];
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
		hashFunction( hashInfo, NULL, packetHeader, 1 + 2, HASH_START );
		hashFunction( hashInfo, hash, buffer, length, HASH_END );
		memcpy( publicKey->openPgpKeyID, 
				hash + hashSize - PGP_KEYID_SIZE, PGP_KEYID_SIZE );
		sMemClose( &stream );
		}
	else
		/* No creation time, fake it */
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

	/* Read the SubjectPublicKeyInfo header field and parameter data if
	   there's any present.  We read the outer wrapper in generic form since
	   it may be context-specific-tagged if it's coming from a keyset (RSA
	   public keys is the one place where PKCS #15 keys differ from X.509
	   ones) or something odd from CRMF */
	readGenericHole( stream, NULL, DEFAULT_TAG );
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
	readBitStringHole( stream, NULL, DEFAULT_TAG );
	readSequence( stream, NULL );
	readBignum( stream, &rsaKey->rsaParam_n );
	return( readBignum( stream, &rsaKey->rsaParam_e ) );
	}

static int readDlpSubjectPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
									int *actionFlags )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	CRYPT_ALGO_TYPE cryptAlgo;
	int extraLength, status;

	/* Read the SubjectPublicKeyInfo header field and parameter data if
	   there's any present */
	readGenericHole( stream, NULL, DEFAULT_TAG );
	status = readAlgoIDex( stream, &cryptAlgo, NULL, &extraLength );
	if( cryptStatusOK( status ) && extraLength )
		{
		assert( contextInfoPtr->capabilityInfo->cryptAlgo == cryptAlgo );

		/* Read the header and key parameters */
		readSequence( stream, NULL );
		readBignum( stream, &dlpKey->dlpParam_p );
		if( hasReversedParams( cryptAlgo ) )
			{
			readBignum( stream, &dlpKey->dlpParam_g );
			status = readBignum( stream, &dlpKey->dlpParam_q );
			}
		else
			{
			readBignum( stream, &dlpKey->dlpParam_q );
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
	readBitStringHole( stream, NULL, DEFAULT_TAG );
	return( readBignum( stream, &dlpKey->dlpParam_y ) );
	}

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

	assert( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

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

/* Read SSHv2 public keys:

	string	certificate
		string	"ssh-rsa"	"ssh-dss"
		mpint	e			p
		mpint	n			q
		mpint				g
		mpint				y */

int readSsh2RsaPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
						  int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	char buffer[ 16 ];
	int length, status;

	assert( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

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

int readSsh2DlpPublicKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
						  int *actionFlags )
	{
	PKC_INFO *dsaKey = contextInfoPtr->ctxPKC;
	const BOOLEAN isDH = \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH );
	char buffer[ 16 ];
	int length, status;

	assert( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH );

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

/* Read PGP public keys:

	byte		version
	uint32		creationTime
	[ uint16	validity - version 3 only ]
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

	assert( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

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

	assert( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
			contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL );

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

/* Umbrella public-key read functions */

static int readPublicKeyRsaFunction( STREAM *stream, CONTEXT_INFO *contextInfoPtr,
									 const KEYFORMAT_TYPE formatType )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			status = readRsaSubjectPublicKey( stream, contextInfoPtr, 
											  &actionFlags );
			break;

		case KEYFORMAT_SSH1:
			status = readSsh1RsaPublicKey( stream, contextInfoPtr, 
										   &actionFlags );
			break;

		case KEYFORMAT_SSH2:
			status = readSsh2RsaPublicKey( stream, contextInfoPtr, 
										   &actionFlags );
			break;

		case KEYFORMAT_PGP:
			status = readPgpRsaPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;

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
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			status = readDlpSubjectPublicKey( stream, contextInfoPtr, 
											  &actionFlags );
			break;

		case KEYFORMAT_SSH2:
			status = readSsh2DlpPublicKey( stream, contextInfoPtr, 
										   &actionFlags );
			break;
		
		case KEYFORMAT_PGP:
			status = readPgpDlpPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;

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
*								Write Public Keys							*
*																			*
****************************************************************************/

/* Write X.509 SubjectPublicKeyInfo public keys */

static int writeRsaSubjectPublicKey( STREAM *stream, 
									 const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	const int length = sizeofBignum( &rsaKey->rsaParam_n ) + \
					   sizeofBignum( &rsaKey->rsaParam_e );

	/* Write the SubjectPublicKeyInfo header field (the +1 is for the 
	   bitstring) */
	writeSequence( stream, sizeofAlgoID( CRYPT_ALGO_RSA ) + \
						   ( int ) sizeofObject( \
										sizeofObject( length ) + 1 ) );
	writeAlgoID( stream, CRYPT_ALGO_RSA );

	/* Write the BITSTRING wrapper and the PKC information */
	writeBitStringHole( stream, ( int ) sizeofObject( length ), 
						DEFAULT_TAG );
	writeSequence( stream, length );
	writeBignum( stream, &rsaKey->rsaParam_n );
	return( writeBignum( stream, &rsaKey->rsaParam_e ) );
	}

static int writeDlpSubjectPublicKey( STREAM *stream, 
									 const CONTEXT_INFO *contextInfoPtr )
	{
	const CRYPT_ALGO_TYPE cryptAlgo = contextInfoPtr->capabilityInfo->cryptAlgo;
	const PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	const int parameterSize = ( int ) sizeofObject( \
								sizeofBignum( &dlpKey->dlpParam_p ) + \
								sizeofBignum( &dlpKey->dlpParam_q ) + \
								sizeofBignum( &dlpKey->dlpParam_g ) );
	const int componentSize = sizeofBignum( &dlpKey->dlpParam_y );
	int totalSize;

	/* Determine the size of the AlgorithmIdentifier and the BITSTRING-
	   encapsulated public-key data (the +1 is for the bitstring) */
	totalSize = sizeofAlgoIDex( cryptAlgo, CRYPT_ALGO_NONE, parameterSize ) + \
				( int ) sizeofObject( componentSize + 1 );

	/* Write the SubjectPublicKeyInfo header field */
	writeSequence( stream, totalSize );
	writeAlgoIDex( stream, cryptAlgo, CRYPT_ALGO_NONE, parameterSize );

	/* Write the parameter data */
	writeSequence( stream, sizeofBignum( &dlpKey->dlpParam_p ) + \
						   sizeofBignum( &dlpKey->dlpParam_q ) + \
						   sizeofBignum( &dlpKey->dlpParam_g ) );
	writeBignum( stream, &dlpKey->dlpParam_p );
	if( hasReversedParams( cryptAlgo ) )
		{
		writeBignum( stream, &dlpKey->dlpParam_g );
		writeBignum( stream, &dlpKey->dlpParam_q );
		}
	else
		{
		writeBignum( stream, &dlpKey->dlpParam_q );
		writeBignum( stream, &dlpKey->dlpParam_g );
		}

	/* Write the BITSTRING wrapper and the PKC information */
	writeBitStringHole( stream, componentSize, DEFAULT_TAG );
	return( writeBignum( stream, &dlpKey->dlpParam_y ) );
	}

/* Write SSH public keys */

static int writeSsh1RsaPublicKey( STREAM *stream, 
								  const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;

	writeUint32( stream, BN_num_bits( &rsaKey->rsaParam_n ) );
	writeBignumInteger16Ubits( stream, &rsaKey->rsaParam_e );
	return( writeBignumInteger16Ubits( stream, &rsaKey->rsaParam_n ) );
	}

static int writeSsh2RsaPublicKey( STREAM *stream, 
								  const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;

	writeUint32( stream, sizeofString32( 7 ) + \
						 sizeofBignumInteger32( &rsaKey->rsaParam_e ) + \
						 sizeofBignumInteger32( &rsaKey->rsaParam_n ) );
	writeString32( stream, "ssh-rsa", 7 );
	writeBignumInteger32( stream, &rsaKey->rsaParam_e );
	return( writeBignumInteger32( stream, &rsaKey->rsaParam_n ) );
	}

static int writeSsh2DlpPublicKey( STREAM *stream, 
								  const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *dsaKey = contextInfoPtr->ctxPKC;

	/* SSHv2 uses PKCS #3 rather than X9.42-style DH keys, so we have to 
	   treat this algorithm type specially */
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH )
		{
		writeUint32( stream, sizeofString32( 6 ) + \
							 sizeofBignumInteger32( &dsaKey->dlpParam_p ) + \
							 sizeofBignumInteger32( &dsaKey->dlpParam_g ) );
		writeString32( stream, "ssh-dh", 6 );
		writeBignumInteger32( stream, &dsaKey->dlpParam_p );
		return( writeBignumInteger32( stream, &dsaKey->dlpParam_g ) );
		}

	writeUint32( stream, sizeofString32( 7 ) + \
						 sizeofBignumInteger32( &dsaKey->dlpParam_p ) + \
						 sizeofBignumInteger32( &dsaKey->dlpParam_q ) + \
						 sizeofBignumInteger32( &dsaKey->dlpParam_g ) + \
						 sizeofBignumInteger32( &dsaKey->dlpParam_y ) );
	writeString32( stream, "ssh-dss", 7 );
	writeBignumInteger32( stream, &dsaKey->dlpParam_p );
	writeBignumInteger32( stream, &dsaKey->dlpParam_q );
	writeBignumInteger32( stream, &dsaKey->dlpParam_g );
	return( writeBignumInteger32( stream, &dsaKey->dlpParam_y ) );
	}

/* Write PGP public keys */

int writePgpRsaPublicKey( STREAM *stream, const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;

	sputc( stream, PGP_VERSION_OPENPGP );
	writeUint32Time( stream, rsaKey->pgpCreationTime );
	sputc( stream, PGP_ALGO_RSA );
	writeBignumInteger16Ubits( stream, &rsaKey->rsaParam_n );
	return( writeBignumInteger16Ubits( stream, &rsaKey->rsaParam_e ) );
	}

int writePgpDlpPublicKey( STREAM *stream, const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	const CRYPT_ALGO_TYPE cryptAlgo = contextInfoPtr->capabilityInfo->cryptAlgo;

	sputc( stream, PGP_VERSION_OPENPGP );
	writeUint32Time( stream, dlpKey->pgpCreationTime );
	sputc( stream, ( cryptAlgo == CRYPT_ALGO_DSA ) ? \
		   PGP_ALGO_DSA : PGP_ALGO_ELGAMAL );
	writeBignumInteger16Ubits( stream, &dlpKey->dlpParam_p );
	if( cryptAlgo == CRYPT_ALGO_DSA )
		writeBignumInteger16Ubits( stream, &dlpKey->dlpParam_q );
	writeBignumInteger16Ubits( stream, &dlpKey->dlpParam_g );
	return( writeBignumInteger16Ubits( stream, &dlpKey->dlpParam_y ) );
	}

/* Umbrella public-key write functions */

static int writePublicKeyRsaFunction( STREAM *stream, 
									  const CONTEXT_INFO *contextInfoPtr,
									  const KEYFORMAT_TYPE formatType,
									  const char *accessKey )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	/* Make sure that we really intended to call this function */
	if( strcmp( accessKey, "public" ) )
		return( CRYPT_ERROR_PERMISSION );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			return( writeRsaSubjectPublicKey( stream, contextInfoPtr ) );

		case KEYFORMAT_SSH1:
			return( writeSsh1RsaPublicKey( stream, contextInfoPtr ) );

		case KEYFORMAT_SSH2:
			return( writeSsh2RsaPublicKey( stream, contextInfoPtr ) );

		case KEYFORMAT_PGP:
			return( writePgpRsaPublicKey( stream, contextInfoPtr ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int writePublicKeyDlpFunction( STREAM *stream, 
									  const CONTEXT_INFO *contextInfoPtr,
									  const KEYFORMAT_TYPE formatType,
									  const char *accessKey )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	/* Make sure that we really intended to call this function */
	if( strcmp( accessKey, "public" ) )
		return( CRYPT_ERROR_PERMISSION );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			return( writeDlpSubjectPublicKey( stream, contextInfoPtr ) );

		case KEYFORMAT_SSH2:
			return( writeSsh2DlpPublicKey( stream, contextInfoPtr ) );

		case KEYFORMAT_PGP:
			return( writePgpDlpPublicKey( stream, contextInfoPtr ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
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
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	/* Read the header and key components */
	readSequence( stream, NULL );
	if( peekTag( stream ) == MAKE_CTAG( 0 ) )
		/* Erroneously written in older code */
		readConstructed( stream, NULL, 0 );
	if( peekTag( stream ) == MAKE_CTAG_PRIMITIVE( 0 ) )
		{
		readBignumTag( stream, &rsaKey->rsaParam_n, 0 );
		readBignumTag( stream, &rsaKey->rsaParam_e, 1 );
		}
	if( peekTag( stream ) == MAKE_CTAG_PRIMITIVE( 2 ) )
		readBignumTag( stream, &rsaKey->rsaParam_d, 2 );
	readBignumTag( stream, &rsaKey->rsaParam_p, 3 );
	status = readBignumTag( stream, &rsaKey->rsaParam_q, 4 );
	if( peekTag( stream ) == MAKE_CTAG_PRIMITIVE( 5 ) )
		{
		readBignumTag( stream, &rsaKey->rsaParam_exponent1, 5 );
		readBignumTag( stream, &rsaKey->rsaParam_exponent2, 6 );
		status = readBignumTag( stream, &rsaKey->rsaParam_u, 7 );
		}
	return( status );
	}

static int readRsaPrivateKeyOld( STREAM *stream, CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	/* Read the header and key components */
	readOctetStringHole( stream, NULL, DEFAULT_TAG );
	readSequence( stream, NULL );
	readShortInteger( stream, NULL );
	readBignum( stream, &rsaKey->rsaParam_n );
	readBignum( stream, &rsaKey->rsaParam_e );
	readBignum( stream, &rsaKey->rsaParam_d );
	readBignum( stream, &rsaKey->rsaParam_p );
	readBignum( stream, &rsaKey->rsaParam_q );
	readBignum( stream, &rsaKey->rsaParam_exponent1 );
	readBignum( stream, &rsaKey->rsaParam_exponent2 );
	return( readBignum( stream, &rsaKey->rsaParam_u ) );
	}

static int readDlpPrivateKey( STREAM *stream, CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

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
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

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
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

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
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( readRsaPrivateKey( stream, contextInfoPtr ) );

		case KEYFORMAT_PRIVATE_OLD:
			return( readRsaPrivateKeyOld( stream, contextInfoPtr ) );

		case KEYFORMAT_PGP:
			return( readPgpRsaPrivateKey( stream, contextInfoPtr ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int readPrivateKeyDlpFunction( STREAM *stream, 
									  CONTEXT_INFO *contextInfoPtr,
									  const KEYFORMAT_TYPE formatType )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( readDlpPrivateKey( stream, contextInfoPtr ) );

		case KEYFORMAT_PGP:
			return( readPgpDlpPrivateKey( stream, contextInfoPtr ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*								Write Private Keys							*
*																			*
****************************************************************************/

/* Write private keys */

static int writeRsaPrivateKey( STREAM *stream, 
							   const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int length = sizeofBignum( &rsaKey->rsaParam_p ) + \
				 sizeofBignum( &rsaKey->rsaParam_q );

	/* Add the length of any optional components that may be present */
#ifdef OLD_MODE	/* Erroneously written in older code */
	if( !BN_is_zero( &rsaKey->rsaParam_n ) )
		length += sizeofBignum( &rsaKey->rsaParam_n ) + \
				  sizeofBignum( &rsaKey->rsaParam_e );
	if( !BN_is_zero( &rsaKey->rsaParam_d ) )
		length += sizeofBignum( &rsaKey->rsaParam_d );
#endif /* 1 */
	if( !BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		{
		length += sizeofBignum( &rsaKey->rsaParam_exponent1 ) + \
				  sizeofBignum( &rsaKey->rsaParam_exponent2 ) + \
				  sizeofBignum( &rsaKey->rsaParam_u );
		}

	/* Write the the PKC fields */
#ifdef OLD_MODE	/* Erroneously written in older code */
	writeSequence( stream,
				   ( int ) sizeofObject( length ) + \
				   sizeofShortInteger( BN_num_bits( &rsaKey->rsaParam_n ) ) );
	writeConstructed( stream, length, 0 );
	if( !BN_is_zero( &rsaKey->rsaParam_n ) )
		{
		writeBignumTag( stream, &rsaKey->rsaParam_n, 0 );
		writeBignumTag( stream, &rsaKey->rsaParam_e, 1 );
		}
	if( !BN_is_zero( &rsaKey->rsaParam_d ) )
		writeBignumTag( stream, &rsaKey->rsaParam_d, 2 );
	writeBignumTag( stream, &rsaKey->rsaParam_p, 3 );
	writeBignumTag( stream, &rsaKey->rsaParam_q, 4 );
	if( !BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		{
		writeBignumTag( stream, &rsaKey->rsaParam_exponent1, 5 );
		writeBignumTag( stream, &rsaKey->rsaParam_exponent2, 6 );
		writeBignumTag( stream, &rsaKey->rsaParam_u, 7 );
		}
	return( writeShortInteger( stream, BN_num_bits( &rsaKey->rsaParam_n ), 
							   DEFAULT_TAG ) );
#else
	writeSequence( stream, length );
	writeBignumTag( stream, &rsaKey->rsaParam_p, 3 );
	if( BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		return( writeBignumTag( stream, &rsaKey->rsaParam_q, 4 ) );
	writeBignumTag( stream, &rsaKey->rsaParam_q, 4 );
	writeBignumTag( stream, &rsaKey->rsaParam_exponent1, 5 );
	writeBignumTag( stream, &rsaKey->rsaParam_exponent2, 6 );
	return( writeBignumTag( stream, &rsaKey->rsaParam_u, 7 ) );
#endif /* 1 */
	}

static int writeRsaPrivateKeyOld( STREAM *stream, 
								  const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	const int length = sizeofShortInteger( 0 ) + \
					   sizeofBignum( &rsaKey->rsaParam_n ) + \
					   sizeofBignum( &rsaKey->rsaParam_e ) + \
					   sizeofBignum( &rsaKey->rsaParam_d ) + \
					   sizeofBignum( &rsaKey->rsaParam_p ) + \
					   sizeofBignum( &rsaKey->rsaParam_q ) + \
					   sizeofBignum( &rsaKey->rsaParam_exponent1 ) + \
					   sizeofBignum( &rsaKey->rsaParam_exponent2 ) + \
					   sizeofBignum( &rsaKey->rsaParam_u );

	/* The older format is somewhat restricted in terms of what can be
	   written since all components must be present, even the ones that are
	   never used.  If anything is missing, we can't write the key since
	   nothing would be able to read it */
	if( BN_is_zero( &rsaKey->rsaParam_n ) || \
		BN_is_zero( &rsaKey->rsaParam_d ) || \
		BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Write the the PKC fields */
	writeSequence( stream, sizeofShortInteger( 0 ) + \
						   sizeofAlgoID( CRYPT_ALGO_RSA ) + \
						   ( int ) sizeofObject( \
										sizeofObject( length ) ) );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeAlgoID( stream, CRYPT_ALGO_RSA );
	writeOctetStringHole( stream, ( int ) sizeofObject( length ), 
						  DEFAULT_TAG );
	writeSequence( stream, length );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeBignum( stream, &rsaKey->rsaParam_n );
	writeBignum( stream, &rsaKey->rsaParam_e );
	writeBignum( stream, &rsaKey->rsaParam_d );
	writeBignum( stream, &rsaKey->rsaParam_p );
	writeBignum( stream, &rsaKey->rsaParam_q );
	writeBignum( stream, &rsaKey->rsaParam_exponent1 );
	writeBignum( stream, &rsaKey->rsaParam_exponent2 );
	return( writeBignum( stream, &rsaKey->rsaParam_u ) );
	}

/* Umbrella private-key write functions */

static int writePrivateKeyRsaFunction( STREAM *stream, 
									   const CONTEXT_INFO *contextInfoPtr,
									   const KEYFORMAT_TYPE formatType,
									   const char *accessKey )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	/* Make sure that we really intended to call this function */
	if( strcmp( accessKey, "private" ) )
		return( CRYPT_ERROR_PERMISSION );

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( writeRsaPrivateKey( stream, contextInfoPtr ) );

		case KEYFORMAT_PRIVATE_OLD:
			return( writeRsaPrivateKeyOld( stream, contextInfoPtr ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int writePrivateKeyDlpFunction( STREAM *stream, 
									   const CONTEXT_INFO *contextInfoPtr,
									   const KEYFORMAT_TYPE formatType,
									   const char *accessKey )
	{
	const PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	/* Make sure that we really intended to call this function */
	if( strcmp( accessKey, "private" ) )
		return( CRYPT_ERROR_PERMISSION );

	/* When we're generating a DH key ID, only p, q, and g are initialised,
	   so we write a special-case zero y value.  This is a somewhat ugly
	   side-effect of the odd way in which DH "public keys" work */
	if( BN_is_zero( &dlpKey->dlpParam_y ) )
#ifdef OLD_MODE	/* Erroneously written in older code */
		{
		writeSequence( stream, sizeofShortInteger( 0 ) );
		return( writeShortInteger( stream, 0, 0 ) );
		}
#else
		return( writeShortInteger( stream, 0, DEFAULT_TAG ) );
#endif /* 1 */

	/* Write the header and key components */
#ifdef OLD_MODE	/* Erroneously written in older code */
	writeSequence( stream, sizeofBignum( &dlpKey->dlpParam_x ) );
	return( writeBignumTag( stream, &dlpKey->dlpParam_x, 0 ) );
#else
	return( writeBignum( stream, &dlpKey->dlpParam_x ) );
#endif /* 1 */
	}

/****************************************************************************
*																			*
*							Write Flat Public Key Data						*
*																			*
****************************************************************************/

#ifdef USE_KEA

/* Generate KEA domain parameters from flat-format values */

static int generateDomainParameters( BYTE *domainParameters,
									 const void *p, const int pLength,
									 const void *q, const int qLength,
									 const void *g, const int gLength )
	{
	STREAM stream;
	BYTE hash[ CRYPT_MAX_HASHSIZE ];
	BYTE dataBuffer[ 16 + ( CRYPT_MAX_PKCSIZE * 3 ) ];
	HASHFUNCTION hashFunction;
	const int pSize = sizeofInteger( p, pLength );
	const int qSize = sizeofInteger( q, qLength );
	const int gSize = sizeofInteger( g, gLength );
	int hashSize, dataSize, i;

	/* Write the parameters to a stream.  The stream length is in case
	   KEA is at some point extended up to the max.allowed PKC size */
	sMemOpen( &stream, dataBuffer, 16 + ( CRYPT_MAX_PKCSIZE * 3 ) );
	writeSequence( &stream, pSize + qSize + gSize );
	writeInteger( &stream, p, pLength, DEFAULT_TAG );
	writeInteger( &stream, q, qLength, DEFAULT_TAG );
	writeInteger( &stream, g, gLength, DEFAULT_TAG );
	assert( cryptStatusOK( sGetStatus( &stream ) ) );
	dataSize = stell( &stream );
	sMemDisconnect( &stream );

	/* Hash the DSA/KEA parameters and reduce them down to get the domain
	   identifier */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	hashFunction( NULL, hash, dataBuffer, dataSize, HASH_ALL );
	zeroise( dataBuffer, CRYPT_MAX_PKCSIZE * 3 );
	hashSize /= 2;	/* Output = hash result folded in half */
	for( i = 0; i < hashSize; i++ )
		domainParameters[ i ] = hash[ i ] ^ hash[ hashSize + i ];

	return( hashSize );
	}
#endif /* USE_KEA */

/* If the keys are stored in a crypto device rather than being held in the
   context, all we have available are the public components in flat format.
   The following code writes flat-format public components in the X.509
   SubjectPublicKeyInfo format */

int writeFlatPublicKey( void *buffer, const int bufMaxSize, 
						const CRYPT_ALGO_TYPE cryptAlgo, 
						const void *component1, const int component1Length,
						const void *component2, const int component2Length,
						const void *component3, const int component3Length,
						const void *component4, const int component4Length )
	{
	STREAM stream;
	const int comp1Size = sizeofInteger( component1, component1Length );
	const int comp2Size = sizeofInteger( component2, component2Length );
	const int comp3Size = ( component3 == NULL ) ? 0 : \
						  sizeofInteger( component3, component3Length );
	const int comp4Size = ( component4 == NULL ) ? 0 : \
						  sizeofInteger( component4, component4Length );
	const int parameterSize = ( cryptAlgo == CRYPT_ALGO_DSA ) ? \
				( int ) sizeofObject( comp1Size + comp2Size + comp3Size ) : \
							  ( cryptAlgo == CRYPT_ALGO_KEA ) ? \
				( int) sizeofObject( 10 ) : 0;
	const int componentSize = ( cryptAlgo == CRYPT_ALGO_RSA ) ? \
				( int ) sizeofObject( comp1Size + comp2Size ) : \
							  ( cryptAlgo == CRYPT_ALGO_KEA ) ? \
				component4Length : comp4Size;
	int totalSize, status;

	assert( ( buffer == NULL && bufMaxSize == 0 ) || \
			isWritePtr( buffer, bufMaxSize ) );
	assert( isReadPtr( component1, component1Length ) );
	assert( isReadPtr( component2, component2Length ) );
	assert( comp3Size == 0 || isReadPtr( component3, component3Length ) );
	assert( comp4Size == 0 || isReadPtr( component4, component4Length ) );
	assert( cryptAlgo == CRYPT_ALGO_DSA || cryptAlgo == CRYPT_ALGO_KEA || \
			cryptAlgo == CRYPT_ALGO_RSA );

	/* Determine the size of the AlgorithmIdentifier and the BITSTRING-
	   encapsulated public-key data (the +1 is for the bitstring) */
	totalSize = sizeofAlgoIDex( cryptAlgo, CRYPT_ALGO_NONE, parameterSize ) + \
				( int ) sizeofObject( componentSize + 1 );
	if( buffer == NULL )
		/* It's just a size-check call, return the overall size */
		return( ( int ) sizeofObject( totalSize ) );

	sMemOpen( &stream, buffer, bufMaxSize );

	/* Write the SubjectPublicKeyInfo header field */
	writeSequence( &stream, totalSize );
	writeAlgoIDex( &stream, cryptAlgo, CRYPT_ALGO_NONE, parameterSize );

	/* Write the parameter data if necessary */
	if( cryptAlgo == CRYPT_ALGO_DSA )
		{
		writeSequence( &stream, comp1Size + comp2Size + comp3Size );
		writeInteger( &stream, component1, component1Length, DEFAULT_TAG );
		writeInteger( &stream, component2, component2Length, DEFAULT_TAG );
		writeInteger( &stream, component3, component3Length, DEFAULT_TAG );
		}
#ifdef USE_KEA
	if( cryptAlgo == CRYPT_ALGO_KEA )
		{
		BYTE domainParameters[ 10 ];
		const int domainParameterLength = \
					generateDomainParameters( domainParameters,
											  component1, component1Length,
											  component2, component2Length,
											  component3, component3Length );

		writeOctetString( &stream, domainParameters, domainParameterLength,
						  DEFAULT_TAG );
		}
#endif /* USE_KEA */

	/* Write the BITSTRING wrapper and the PKC information */
	writeBitStringHole( &stream, componentSize, DEFAULT_TAG );
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		writeSequence( &stream, comp1Size + comp2Size );
		writeInteger( &stream, component1, component1Length, DEFAULT_TAG );
		writeInteger( &stream, component2, component2Length, DEFAULT_TAG );
		}
	else
		if( cryptAlgo == CRYPT_ALGO_DSA )
			writeInteger( &stream, component4, component4Length, DEFAULT_TAG );
		else
			swrite( &stream, component4, component4Length );

	/* Clean up */
	status = sGetStatus( &stream );
	sMemDisconnect( &stream );
	return( status );
	}

/****************************************************************************
*																			*
*								Read/Write DL Values						*
*																			*
****************************************************************************/

/* Unlike the simpler RSA PKC, DL-based PKCs produce a pair of values that
   need to be encoded as structured data.  The following two functions 
   perform this en/decoding.  SSH assumes that DLP values are two fixed-size
   blocks of 20 bytes, so we can't use the normal read/write routines to 
   handle these values */

int encodeDLValues( BYTE *buffer, const int bufSize, BIGNUM *value1,
					BIGNUM *value2, const CRYPT_FORMAT_TYPE formatType )
	{
	STREAM stream;
	int length;

	sMemOpen( &stream, buffer, bufSize );

	/* Write the DL components to the buffer */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			writeSequence( &stream, sizeofBignum( value1 ) + \
									sizeofBignum( value2 ) );
			writeBignum( &stream, value1 );
			writeBignum( &stream, value2 );
			break;

		case CRYPT_FORMAT_PGP:
			writeBignumInteger16Ubits( &stream, value1 );
			writeBignumInteger16Ubits( &stream, value2 );
			break;

		case CRYPT_IFORMAT_SSH:
			for( length = 0; length < 4; length++ )
				swrite( &stream, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 
						10 );
			length = BN_num_bytes( value1 );
			BN_bn2bin( value1, buffer + 20 - length );
			length = BN_num_bytes( value2 );
			BN_bn2bin( value2, buffer + 40 - length );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}
	assert( sStatusOK( &stream ) );

	/* Clean up */
	length = stell( &stream );
	sMemDisconnect( &stream );
	return( length );
	}

int decodeDLValues( const BYTE *buffer, const int bufSize, BIGNUM **value1,
					BIGNUM **value2, const CRYPT_FORMAT_TYPE formatType )
	{
	STREAM stream;
	int status;

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

		case CRYPT_FORMAT_PGP:
			status = readBignumInteger16Ubits( &stream, *value1, 160 - 24,
											   bytesToBits( PGP_MAX_MPISIZE ) );
			if( cryptStatusOK( status ) )
				status = readBignumInteger16Ubits( &stream, *value2, 160 - 24,
												   bytesToBits( PGP_MAX_MPISIZE ) );
			break;
	
		case CRYPT_IFORMAT_SSH:
			status = CRYPT_OK;
			if( BN_bin2bn( buffer, 20, *value1 ) == NULL || \
				BN_bin2bn( buffer + 20, 20, *value2 ) == NULL )
				status = CRYPT_ERROR_MEMORY;
			break;

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

void initKeyReadWrite( CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

	/* Set the access method pointers */
	if( isDlpAlgo( contextInfoPtr->capabilityInfo->cryptAlgo ) )
		{
		pkcInfo->readPublicKeyFunction = readPublicKeyDlpFunction;
		pkcInfo->readPrivateKeyFunction = readPrivateKeyDlpFunction;
		pkcInfo->writePublicKeyFunction = writePublicKeyDlpFunction;
		pkcInfo->writePrivateKeyFunction = writePrivateKeyDlpFunction;
		}
	else
		{
		pkcInfo->readPublicKeyFunction = readPublicKeyRsaFunction;
		pkcInfo->readPrivateKeyFunction = readPrivateKeyRsaFunction;
		pkcInfo->writePublicKeyFunction = writePublicKeyRsaFunction;
		pkcInfo->writePrivateKeyFunction = writePrivateKeyRsaFunction;
		}
	}
