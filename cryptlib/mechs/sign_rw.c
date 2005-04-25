/****************************************************************************
*																			*
*						  Signature Read/Write Routines						*
*						Copyright Peter Gutmann 1992-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) 
  #include "pgp.h"
  #include "asn1.h"
  #include "mechanism.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
#elif defined( INC_CHILD )
  #include "../envelope/pgp.h"
  #include "mechanism.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
  #include "../misc/misc_rw.h"
#else
  #include "envelope/pgp.h"
  #include "mechs/mechanism.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

/* Context-specific tags for the SignerInfo record */

enum { CTAG_SI_SKI };

/* CMS version numbers for various objects */

#define SIGNATURE_VERSION		1
#define SIGNATURE_EX_VERSION	3

/****************************************************************************
*																			*
*							X.509 Signature Routines						*
*																			*
****************************************************************************/

/* Read/write raw signatures */

static int readRawSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	int status;

	/* Read the start of the signature */
	status = readBitStringHole( stream, &queryInfo->dataLength, 
								DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		queryInfo->dataStart = sMemBufPtr( stream );
	return( status );
	}

static int writeRawSignature( STREAM *stream, const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo, 
							  const CRYPT_ALGO_TYPE signAlgo, 
							  const BYTE *signature, 
							  const int signatureLength )
	{
	/* Write the BIT STRING wrapper and signature */
	writeBitStringHole( stream, signatureLength, DEFAULT_TAG );
	return( writeRawObject( stream, signature, signatureLength ) );
	}

/* Read/write X.509 signatures */

static int readX509Signature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	int status;

	/* Read the signature/hash algorithm information followed by the start 
	   of the signature */
	status = readAlgoIDex( stream, &queryInfo->cryptAlgo,
						   &queryInfo->hashAlgo, NULL );
	if( cryptStatusError( status ) )
		return( status );
	status = readBitStringHole( stream, &queryInfo->dataLength, 
								DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		queryInfo->dataStart = sMemBufPtr( stream );
	return( status );
	}

static int writeX509Signature( STREAM *stream, 
							   const CRYPT_CONTEXT iSignContext,
							   const CRYPT_ALGO_TYPE hashAlgo, 
							   const CRYPT_ALGO_TYPE signAlgo, 
							   const BYTE *signature, 
							   const int signatureLength )
	{
	/* Write the hash+signature algorithm identifier followed by the BIT 
	   STRING wrapper and signature */
	writeContextAlgoID( stream, iSignContext, hashAlgo,
						ALGOID_FLAG_ALGOID_ONLY );
	writeBitStringHole( stream, signatureLength, DEFAULT_TAG );
	return( writeRawObject( stream, signature, signatureLength ) );
	}

/****************************************************************************
*																			*
*							CMS Signature Routines							*
*																			*
****************************************************************************/

/* Read/write PKCS #7/CMS (issuerAndSerialNumber) signatures */

static int readCmsSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	long value, endPos;
	int status;

	value = getStreamObjectLength( stream );
	if( cryptStatusError( value ) )
		return( value );
	endPos = stell( stream ) + value;

	/* Read the header */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusOK( status ) && value != SIGNATURE_VERSION )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		return( status );

	/* Read the issuer and serial number and hash algorithm ID */
	value = getStreamObjectLength( stream );
	if( cryptStatusError( value ) )
		return( value );
	queryInfo->iAndSStart = sMemBufPtr( stream );
	queryInfo->iAndSLength = value;
	sSkip( stream, value );
	status = readAlgoID( stream, &queryInfo->hashAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the authenticated attributes if there are any present */
	if( peekTag( stream ) == MAKE_CTAG( 0 ) )
		{
		int length;

		queryInfo->attributeStart = sMemBufPtr( stream );
		status = readConstructed( stream, &length, 0 );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->attributeLength = ( int ) sizeofObject( length );
		sSkip( stream, length );
		}

	/* Read the CMS/cryptlib signature algorithm and start of the signature */
	readAlgoID( stream, &queryInfo->cryptAlgo );
	status = readOctetStringHole( stream, &queryInfo->dataLength, 
								  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		queryInfo->dataStart = sMemBufPtr( stream );
		status = sSkip( stream, queryInfo->dataLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the unauthenticated attributes if there are any present */
	if( stell( stream ) < endPos && peekTag( stream ) == MAKE_CTAG( 1 ) )
		{
		int length;

		queryInfo->unauthAttributeStart = sMemBufPtr( stream );
		status = readConstructed( stream, &length, 1 );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->unauthAttributeLength = ( int ) sizeofObject( length );
		status = sSkip( stream, length );
		}
	return( status );
	}

static int writeCmsSignature( STREAM *stream, 
							  const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo, 
							  const CRYPT_ALGO_TYPE signAlgo, 
							  const BYTE *signature, 
							  const int signatureLength )
	{
	/* Write the signature algorithm identifier and signature data.  The 
	   handling of CMS signatures is non-orthogonal to readCmsSignature() 
	   because creating a CMS signature involves adding assorted additional 
	   data like iAndS and signed attributes which present too much 
	   information to pass into a basic writeSignature() call */
	writeContextAlgoID( stream, iSignContext, CRYPT_ALGO_NONE,
						ALGOID_FLAG_ALGOID_ONLY );
	return( writeOctetString( stream, signature, signatureLength, DEFAULT_TAG ) );
	}

/* Read/write cryptlib/CMS (keyID) signatures */

static int readCryptlibSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	long value;
	int status;

	/* Read the header */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusOK( status ) && value != SIGNATURE_EX_VERSION )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		return( status );

	/* Read the key ID and hash algorithm identifier */
	readOctetStringTag( stream, queryInfo->keyID, &queryInfo->keyIDlength, 
						CRYPT_MAX_HASHSIZE, CTAG_SI_SKI );
	status = readAlgoID( stream, &queryInfo->hashAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the CMS/cryptlib signature algorithm and start of the signature */
	readAlgoID( stream, &queryInfo->cryptAlgo );
	status = readOctetStringHole( stream, &queryInfo->dataLength, 
								  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		queryInfo->dataStart = sMemBufPtr( stream );
	return( status );
	}

static int writeCryptlibSignature( STREAM *stream, 
								   const CRYPT_CONTEXT iSignContext,
								   const CRYPT_ALGO_TYPE hashAlgo, 
								   const CRYPT_ALGO_TYPE signAlgo, 
								   const BYTE *signature, 
								   const int signatureLength )
	{
	RESOURCE_DATA msgData;
	BYTE keyID[ CRYPT_MAX_HASHSIZE ];

	/* Get the key ID */
	setMessageData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S,
					 &msgData, CRYPT_IATTRIBUTE_KEYID );

	/* Write the header */
	writeSequence( stream, ( int ) sizeofShortInteger( SIGNATURE_EX_VERSION ) + \
				   sizeofObject( msgData.length ) + \
				   sizeofContextAlgoID( iSignContext, CRYPT_ALGO_NONE, \
										ALGOID_FLAG_ALGOID_ONLY ) + \
				   sizeofAlgoID( hashAlgo ) + \
				   sizeofObject( signatureLength ) );

	/* Write the version, key ID and algorithm identifier */
	writeShortInteger( stream, SIGNATURE_EX_VERSION, DEFAULT_TAG );
	writeOctetString( stream, msgData.data, msgData.length, CTAG_SI_SKI );
	writeAlgoID( stream, hashAlgo );
	writeContextAlgoID( stream, iSignContext, CRYPT_ALGO_NONE,
						ALGOID_FLAG_ALGOID_ONLY );
	return( writeOctetString( stream, signature, signatureLength, DEFAULT_TAG ) );
	}

/****************************************************************************
*																			*
*							Misc Signature Routines							*
*																			*
****************************************************************************/

#ifdef USE_PGP

/* Read signature subpackets */

static int readSignatureSubpackets( STREAM *stream, QUERY_INFO *queryInfo,
									const int length, 
									const BOOLEAN isAuthenticated )
	{
	const int endPos = stell( stream ) + length;

	while( stell( stream ) < endPos )
		{
		const int subpacketLength = pgpReadShortLength( stream,
														PGP_CTB_OPENPGP );
		const int type = sgetc( stream );

		if( cryptStatusError( subpacketLength ) )
			return( subpacketLength );

		/* If it's an unrecognised subpacket with the critical flag set,
		   reject the signature.  The range check isn't complete since there
		   are a few holes in the range, but since the holes presumably exist
		   because of deprecated subpacket types, any new packets will be
		   added at the end so it's safe to use */
		if( ( type & 0x80 ) && ( ( type & 0x7F ) > PGP_SUBPACKET_LAST ) )
			return( CRYPT_ERROR_NOTAVAIL );

		/* If it's a key ID and we haven't already set this from a preceding
		   one-pass signature packet (which can happen with detached sigs),
		   set it now */
		if( type == PGP_SUBPACKET_KEYID && queryInfo->keyIDlength <= 0 )
			{
			sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
			queryInfo->keyIDlength = PGP_KEYID_SIZE;
			continue;
			}

		/* If it's a type-and-value packet, see whether it's one of
		   ours */
		if( type == PGP_SUBPACKET_TYPEANDVALUE )
			{
			BYTE nameBuffer[ 32 ];
			static const char *nameString = "issuerAndSerialNumber";
			int nameLength, valueLength;

			sSkip( stream, 4 );		/* Flags */
			nameLength = readUint16( stream );
			valueLength = readUint16( stream );
			if( nameLength != strlen( nameString ) || \
				valueLength < 16 || valueLength > 2048 )
				{
				sSkip( stream, nameLength + valueLength );
				continue;
				}
			sread( stream, nameBuffer, nameLength );
			if( memcmp( nameBuffer, nameString, nameLength ) )
				{
				sSkip( stream, valueLength );
				continue;
				}

			/* It's an issuerAndSerialNumber, remember it for later */
			queryInfo->iAndSStart = sMemBufPtr( stream );
			queryInfo->iAndSLength = valueLength;
			sSkip( stream, valueLength );
			continue;
			}

		/* It's something else, skip it and continue */
		sSkip( stream, subpacketLength - 1 );
		}

	return( sGetStatus( stream ) );
	}

/* Signature info:
		byte	ctb = PGP_PACKET_SIGNATURE_ONEPASS
		byte[]	length
		byte	version = 3
		byte	sigType
		byte	hashAlgo
		byte	sigAlgo
		byte[8]	keyID
		byte	1 */

int readOnepassSigPacket( STREAM *stream, QUERY_INFO *queryInfo )
	{
	int status;

	/* Make sure that the packet header is in order and check the packet 
	   version.  This is an OpenPGP-only packet */
	status = getPacketInfo( stream, queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( sgetc( stream ) != PGP_VERSION_3 )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->version = PGP_VERSION_OPENPGP;

	/* Skip the sig.type, get the hash algorithm and check the signature 
	   algorithm */
	sgetc( stream );
	if( ( queryInfo->hashAlgo = \
			pgpToCryptlibAlgo( sgetc( stream ),
							   PGP_ALGOCLASS_HASH ) ) == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );
	if( ( queryInfo->cryptAlgo = \
			pgpToCryptlibAlgo( sgetc( stream ),
							   PGP_ALGOCLASS_SIGN ) ) == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );
	queryInfo->type = CRYPT_OBJECT_SIGNATURE;

	/* Get the PGP key ID and make sure that this isn't a nested signature */
	status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->keyIDlength = PGP_KEYID_SIZE;
	return( ( sgetc( stream ) != 1 ) ? CRYPT_ERROR_BADDATA : CRYPT_OK );
	}

/* Read/write PGP signatures.

		byte	ctb = PGP_PACKET_SIGNATURE
		byte[]	length
	v3:	byte	version = 2, 3		v4: byte	version = 4
		byte	infoLen = 5			byte	sigType
			byte	sigType			byte	sigAlgo
			byte[4]	sig.time		byte	hashAlgo
		byte[8]	keyID				byte[2]	length of auth.attributes
		byte	sigAlgo				byte[]	authenticated attributes
		byte	hashAlgo			byte[2]	length of unauth.attributes
		byte[2]	hash check			byte[]	unauthenticated attributes
		mpi(s)	signature			byte[2]	hash check
									mpi(s)	signature */

static int readPgpSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	int value, status;

	/* Make sure that the packet header is in order and check the packet 
	   version.  For this packet type, a version number of 3 denotes PGP 2.x, 
	   whereas for key transport it denotes OpenPGP */
	status = getPacketInfo( stream, queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	value = sgetc( stream );
	if( value != PGP_VERSION_2 && value != PGP_VERSION_3 && \
		value != PGP_VERSION_OPENPGP )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->type = CRYPT_OBJECT_SIGNATURE;
	queryInfo->version = ( value == PGP_VERSION_OPENPGP ) ? \
						 PGP_VERSION_OPENPGP : PGP_VERSION_2;

	/* If it's not an OpenPGP packet, read it as a PGP 2.x-format
	   signature */
	if( value != PGP_VERSION_OPENPGP )
		{
		/* Read the additional signature information */
		if( sgetc( stream ) != 5 )
			return( CRYPT_ERROR_BADDATA );
		queryInfo->attributeStart = sMemBufPtr( stream );
		queryInfo->attributeLength = 5;
		sSkip( stream, 5 );

		/* Read the signer keyID, signature and hash algorithm */
		status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->keyIDlength = PGP_KEYID_SIZE;
		if( ( queryInfo->cryptAlgo = \
				pgpToCryptlibAlgo( sgetc( stream ),
								   PGP_ALGOCLASS_SIGN ) ) == CRYPT_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );
		if( ( queryInfo->hashAlgo = \
				pgpToCryptlibAlgo( sgetc( stream ),
								   PGP_ALGOCLASS_HASH ) ) == CRYPT_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );
		}
	else
		{
		/* It's an OpenPGP packet, remember the extra data to be hashed (this
		   starts at the version byte, which we've already read, so we add a 
		   -1 offset) and read the signature and hash algorithms */
		queryInfo->attributeStart = sMemBufPtr( stream ) - 1;
		queryInfo->attributeLength = 1 + 1 + 1 + 1 + 2;
		sgetc( stream );	/* Skip signature type */
		if( ( queryInfo->cryptAlgo = \
				pgpToCryptlibAlgo( sgetc( stream ),
								   PGP_ALGOCLASS_SIGN ) ) == CRYPT_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );
		if( ( queryInfo->hashAlgo = \
				pgpToCryptlibAlgo( sgetc( stream ),
								   PGP_ALGOCLASS_HASH ) ) == CRYPT_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );

		/* Process the authenticated attributes */
		value = readUint16( stream );
		if( value < 0 || value > 2048 )
			return( CRYPT_ERROR_BADDATA );
		if( sMemDataLeft( stream ) < value )
			return( CRYPT_ERROR_UNDERFLOW );
		queryInfo->attributeLength += value;
		if( value > 0 )
			{
			status = readSignatureSubpackets( stream, queryInfo, value, 
											  TRUE );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Skip the unauthenticated attributes */
		queryInfo->unauthAttributeStart = sMemBufPtr( stream );
		value = readUint16( stream );
		if( value < 0 || value > 2048 )
			return( CRYPT_ERROR_BADDATA );
		if( sMemDataLeft( stream ) < value )
			return( CRYPT_ERROR_UNDERFLOW );
		queryInfo->unauthAttributeLength = 2 + value;
		if( value > 0 )
			{
			status = readSignatureSubpackets( stream, queryInfo, value, 
											  FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* Skip the hash check and read the signature, recording the start of the
	   signature data */
	sSkip( stream, 2 );
	if( queryInfo->cryptAlgo == CRYPT_ALGO_DSA )
		{
		queryInfo->dataStart = sMemBufPtr( stream );
		status = pgpReadMPI( stream, NULL );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->dataLength = bitsToBytes( status ) + 2;
		status = pgpReadMPI( stream, NULL );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->dataLength += bitsToBytes( status ) + 2;
		if( queryInfo->dataLength < 20 || \
			queryInfo->dataLength > 44 )
			return( CRYPT_ERROR_BADDATA );
		}
	else
		{
		queryInfo->dataStart = sMemBufPtr( stream ) + 2;
		status = pgpReadMPI( stream, NULL );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->dataLength = bitsToBytes( status );
		if( queryInfo->dataLength < 56 || \
			queryInfo->dataLength > CRYPT_MAX_PKCSIZE + 2 )
			return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
	}

static int writePgpSignature( STREAM *stream, 
							  const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo, 
							  const CRYPT_ALGO_TYPE signAlgo, 
							  const BYTE *signature, 
							  const int signatureLength )
	{
	const int bitLength = bytesToBits( signatureLength );

	/* If it's a DLP algorithm, we've already specified the DLP output 
	   format as PGP so there's no need for further processing.  The 
	   handling of PGP signatures is non-orthogonal to readPgpSignature() 
	   because creating a PGP signature involves adding assorted additional 
	   data like key IDs and authenticated attributes which present too much 
	   information to pass into a basic writeSignature() call */
	if( isDlpAlgo( signAlgo ) )
		return( swrite( stream, signature, signatureLength ) );

	/* Write the signature as PGP MPI */
	sputc( stream, ( bitLength >> 8 ) & 0xFF );
	sputc( stream, bitLength & 0xFF );
	return( swrite( stream, signature, signatureLength ) );
	}
#endif /* USE_PGP */

#ifdef USE_SSH2

/* Read/write SSH signatures.  SSH signature data is treated as a blob 
   encoded as an SSH string rather than properly-formatted data, so we don't 
   encode/decode it as SSH MPIs */

static int readSshSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	BYTE buffer[ 64 + 8 ];
	int length, status;

	/* Read the signature record size and algorithm information */
	readUint32( stream );
	status = readString32( stream, buffer, &length, 64 );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 7 )
		return( CRYPT_ERROR_BADDATA );
	if( !memcmp( buffer, "ssh-rsa", 7 ) )
		queryInfo->cryptAlgo = CRYPT_ALGO_RSA;
	else
		if( !memcmp( buffer, "ssh-dss", 7 ) )
			queryInfo->cryptAlgo = CRYPT_ALGO_DSA;
		else
			return( CRYPT_ERROR_BADDATA );

	/* Read the start of the signature */
	length = readUint32( stream );
	if( cryptStatusError( length ) )
		return( length );
	if( queryInfo->cryptAlgo == CRYPT_ALGO_DSA )
		{
		if( length != 40 || length > sMemDataLeft( stream ) )
			return( CRYPT_ERROR_BADDATA );
		}
	else
		{
		if( length < 56 || length > CRYPT_MAX_PKCSIZE || \
			length > sMemDataLeft( stream ) )
			return( CRYPT_ERROR_BADDATA );
		}
	queryInfo->dataStart = sMemBufPtr( stream );
	queryInfo->dataLength = length;

	return( CRYPT_OK );
	}

static int writeSshSignature( STREAM *stream, 
							  const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo, 
							  const CRYPT_ALGO_TYPE signAlgo, 
							  const BYTE *signature, 
							  const int signatureLength )
	{
	writeUint32( stream, sizeofString32( "ssh-Xsa", 7 ) + \
						 sizeofString32( NULL, signatureLength ) );
	writeString32( stream, ( signAlgo == CRYPT_ALGO_RSA ) ? \
						   "ssh-rsa" : "ssh-dss", 7 );
	return( writeString32( stream, signature, signatureLength ) );
	}
#endif /* USE_SSH2 */

#ifdef USE_SSL

/* Read/write SSL signatures.  This is just a raw signature without any
   encapsulation */

static int readSslSignature( STREAM *stream, QUERY_INFO *queryInfo )
	{
	int length;

	/* Read the start of the signature */
	length = readUint16( stream );
	if( length < 56 || length > CRYPT_MAX_PKCSIZE || \
		length > sMemDataLeft( stream ) )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->dataStart = sMemBufPtr( stream );
	queryInfo->dataLength = length;

	return( CRYPT_OK );
	}

static int writeSslSignature( STREAM *stream, 
							  const CRYPT_CONTEXT iSignContext,
							  const CRYPT_ALGO_TYPE hashAlgo, 
							  const CRYPT_ALGO_TYPE signAlgo, 
							  const BYTE *signature, 
							  const int signatureLength )
	{
	writeUint16( stream, signatureLength );
	return( swrite( stream, signature, signatureLength ) );
	}
#endif /* USE_SSL */

/****************************************************************************
*																			*
*				Signature Read/Write Function Access Information			*
*																			*
****************************************************************************/

const READSIG_FUNCTION sigReadTable[] = {
	NULL,					/* SIGNATURE_NONE */
	readRawSignature,		/* SIGNATURE_RAW */
	readX509Signature,		/* SIGNATURE_X509 */
	readCmsSignature,		/* SIGNATURE_CMS */
	readCryptlibSignature,	/* SIGNATURE_CRYPTLIB */
#ifdef USE_PGP
	readPgpSignature,		/* SIGNATURE_PGP */
#else
	NULL,					/* SIGNATURE_PGP */
#endif /* USE_PGP */
#ifdef USE_SSH2
	readSshSignature,		/* SIGNATURE_SSH */
#else
	NULL,					/* SIGNATURE_SSH */
#endif /* USE_SSH */
#ifdef USE_SSL
	readSslSignature,		/* SIGNATURE_SSL */
#else
	NULL,					/* SIGNATURE_SSL */
#endif /* USE_SSL */
	NULL, NULL, NULL
	};

const WRITESIG_FUNCTION sigWriteTable[] = {
	NULL,					/* SIGNATURE_NONE */
	writeRawSignature,		/* SIGNATURE_RAW */
	writeX509Signature,		/* SIGNATURE_X509 */
	writeCmsSignature,		/* SIGNATURE_CMS */
	writeCryptlibSignature,	/* SIGNATURE_CRYPTLIB */
#ifdef USE_PGP
	writePgpSignature,		/* SIGNATURE_PGP */
#else
	NULL,					/* SIGNATURE_PGP */
#endif /* USE_PGP */
#ifdef USE_SSH2
	writeSshSignature,		/* SIGNATURE_SSH */
#else
	NULL,					/* SIGNATURE_SSH */
#endif /* USE_SSH */
#ifdef USE_SSL
	writeSslSignature,		/* SIGNATURE_SSL */
#else
	NULL,					/* SIGNATURE_SSL */
#endif /* USE_SSH */
	NULL, NULL, NULL
	};
