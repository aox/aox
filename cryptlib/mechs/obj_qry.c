/****************************************************************************
*																			*
*						Encoded Object Query Routines						*
*					  Copyright Peter Gutmann 1992-2006						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "mech.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "mechs/mech.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get information on an ASN.1 object */

static int getObjectInfo( STREAM *stream, QUERY_INFO *queryInfo )
	{
	const long startPos = stell( stream );
	long value;
	int tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* We always need at least MIN_CRYPT_OBJECTSIZE more bytes to do
	   anything */
	if( sMemDataLeft( stream ) < MIN_CRYPT_OBJECTSIZE )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Get the type, length, and version information */
	value = getStreamObjectLength( stream );
	if( cryptStatusError( value ) )
		return( value );
	queryInfo->formatType = CRYPT_FORMAT_CRYPTLIB;
	queryInfo->size = value;
	tag = peekTag( stream );
	readGenericHole( stream, NULL, 16, tag );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->version = value;
	switch( tag )
		{
		case BER_SEQUENCE:
			/* This could be a signature or a PKC-encrypted key, see what
			   follows */
			switch( value )
				{
				case KEYTRANS_VERSION:
				case KEYTRANS_EX_VERSION:
					queryInfo->type = CRYPT_OBJECT_PKCENCRYPTED_KEY;
					break;

				case SIGNATURE_VERSION:
				case SIGNATURE_EX_VERSION:
					queryInfo->type = CRYPT_OBJECT_SIGNATURE;
					break;

				default:
					return( CRYPT_ERROR_BADDATA );
				}
			if( value == KEYTRANS_VERSION || value == SIGNATURE_VERSION )
				queryInfo->formatType = CRYPT_FORMAT_CMS;
			break;

		case MAKE_CTAG( CTAG_RI_KEYAGREE ):
			queryInfo->type = CRYPT_OBJECT_KEYAGREEMENT;
			break;

		case MAKE_CTAG( CTAG_RI_PWRI ):
			queryInfo->type = CRYPT_OBJECT_ENCRYPTED_KEY;
			break;

		default:
			queryInfo->type = CRYPT_OBJECT_NONE;
			if( tag > MAKE_CTAG( CTAG_RI_PWRI ) && \
				tag <= MAKE_CTAG( CTAG_RI_MAX ) )
				/* This is probably a new RecipientInfo type, skip it */
				break;
			return( CRYPT_ERROR_BADDATA );
		}

	/* Reset the stream and make sure that all of the data is present */
	sseek( stream, startPos );
	return( sMemDataLeft( stream ) < queryInfo->size ? \
			CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
	}

#ifdef USE_PGP

/* Get information on a PGP data object.  This doesn't reset the stream like
   the ASN.1 equivalent because the PGP header is complex enough that it
   can't be read inline like the ASN.1 header */

int getPacketInfo( STREAM *stream, QUERY_INFO *queryInfo )
	{
	const long startPos = stell( stream );
	long length;
	int ctb, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Read the packet header and extract information from the CTB.  Note
	   that the assignment of version numbers is speculative only, since
	   it's possible to use PGP 2.x packet headers to wrap up OpenPGP
	   packets */
	status = pgpReadPacketHeader( stream, &ctb, &length, 8 );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->formatType = CRYPT_FORMAT_PGP;
	queryInfo->version = pgpGetPacketVersion( ctb );
	queryInfo->size = length + ( stell( stream ) - startPos );
	switch( pgpGetPacketType( ctb ) )
		{
		case PGP_PACKET_SKE:
			queryInfo->type = CRYPT_OBJECT_ENCRYPTED_KEY;
			break;

		case PGP_PACKET_PKE:
			queryInfo->type = CRYPT_OBJECT_PKCENCRYPTED_KEY;
			break;

		case PGP_PACKET_SIGNATURE:
			queryInfo->type = CRYPT_OBJECT_SIGNATURE;
			break;

		case PGP_PACKET_SIGNATURE_ONEPASS:
			/* First half of a one-pass signature, this is given a special
			   type of 'none' since it's not a normal packet */
			queryInfo->type = CRYPT_OBJECT_NONE;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_BADDATA );
		}

	/* Make sure that all of the data is present without resetting the 
	   stream */
	return( sMemDataLeft( stream ) < ( queryInfo->size - stell( stream ) ) ? \
			CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*								Object Query Routines						*
*																			*
****************************************************************************/

/* Low-level object query functions */

int queryAsn1Object( void *streamPtr, QUERY_INFO *queryInfo )
	{
	STREAM *stream = streamPtr;
	const long startPos = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Clear the return value and determine basic object information.  This 
	   also verifies that all of the object data is present in the stream */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );
	status = getObjectInfo( stream, queryInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Call the appropriate routine to find out more about the object */
	switch( queryInfo->type )
		{
		case CRYPT_OBJECT_ENCRYPTED_KEY:
			{
			const READKEK_FUNCTION readKekFunction = \
									getReadKekFunction( KEYEX_CMS );

			if( readKekFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readKekFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_PKCENCRYPTED_KEY:
			{
			const READKEYTRANS_FUNCTION readKeytransFunction = \
				getReadKeytransFunction( ( queryInfo->formatType == CRYPT_FORMAT_CMS ) ? \
										 KEYEX_CMS : KEYEX_CRYPTLIB );

			if( readKeytransFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readKeytransFunction( stream, queryInfo );
			break;
			}

#if 0	/* 24/11/02 Removed since it was only used for Fortezza */
		case CRYPT_OBJECT_KEYAGREEMENT:
			status = readKeyAgreeInfo( stream, queryInfo, NULL );
			break;
#endif /* 0 */

		case CRYPT_OBJECT_SIGNATURE:
			{
			const READSIG_FUNCTION readSigFunction = \
				getReadSigFunction( ( queryInfo->formatType == CRYPT_FORMAT_CMS ) ? \
									SIGNATURE_CMS : SIGNATURE_CRYPTLIB );

			if( readSigFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readSigFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_NONE:
			/* New, unrecognised RecipientInfo type */
			status = readUniversal( stream );
			break;

		default:
			assert( NOTREACHED );
			status = CRYPT_ERROR_BADDATA;
		}
	sseek( stream, startPos );
	if( cryptStatusError( status ) )
		zeroise( queryInfo, sizeof( QUERY_INFO ) );
	return( status );
	}

#ifdef USE_PGP

int queryPgpObject( void *streamPtr, QUERY_INFO *queryInfo )
	{
	STREAM *stream = streamPtr;
	const long startPos = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Clear the return value and determine basic object information.  This 
	   also verifies that all of the object data is present in the stream */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );
	status = getPacketInfo( stream, queryInfo );
	sseek( stream, startPos );
	if( cryptStatusError( status ) )
		return( status );

	/* Call the appropriate routine to find out more about the object */
	switch( queryInfo->type )
		{
		case CRYPT_OBJECT_ENCRYPTED_KEY:
			{
			const READKEK_FUNCTION readKekFunction = \
									getReadKekFunction( KEYEX_PGP );

			if( readKekFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readKekFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_PKCENCRYPTED_KEY:
			{
			const READKEYTRANS_FUNCTION readKeytransFunction = getReadKeytransFunction( KEYEX_PGP );

			if( readKeytransFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readKeytransFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_SIGNATURE:
			{
			const READSIG_FUNCTION readSigFunction = getReadSigFunction( SIGNATURE_PGP );

			if( readSigFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readSigFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_NONE:
			/* First half of a one-pass signature */
			status = readOnepassSigPacket( stream, queryInfo );
			break;

		default:
			assert( NOTREACHED );
			status = CRYPT_ERROR_BADDATA;
		}
	sseek( stream, startPos );
	if( cryptStatusError( status ) )
		zeroise( queryInfo, sizeof( QUERY_INFO ) );
	return( status );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*						External Object Query Interface						*
*																			*
****************************************************************************/

/* Query an object.  This is just a wrapper that provides an external
   interface for the lower-level object-query routines */

C_RET cryptQueryObject( C_IN void C_PTR objectData,
						C_IN int objectDataLength,
						C_OUT CRYPT_OBJECT_INFO C_PTR cryptObjectInfo )
	{
	QUERY_INFO queryInfo;
	STREAM stream;
	int value, length = objectDataLength, status;

	/* Perform basic error checking and clear the return value.  Although
	   it would be nice to use checkObjectEncoding() to make sure that the
	   input is valid, we can't use it yet at this point because we don't 
	   know whether we've been given ASN.1 data or not */
	if( objectDataLength < MIN_CRYPT_OBJECTSIZE || \
		objectDataLength > MAX_INTLENGTH )
		return( CRYPT_ERROR_PARAM2 );
	if( !isReadPtr( objectData, objectDataLength ) )
		return( CRYPT_ERROR_PARAM1 );
	if( !isWritePtr( cryptObjectInfo, sizeof( CRYPT_OBJECT_INFO ) ) )
		return( CRYPT_ERROR_PARAM3 );
	memset( cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	/* Query the object.  This is just a wrapper for the lower-level object-
	   query functions */
	sMemConnect( &stream, ( void * ) objectData, length );
	value = sPeek( &stream );
	if( value == BER_SEQUENCE || value == MAKE_CTAG( 3 ) )
		status = queryAsn1Object( &stream, &queryInfo );
	else
		{
#ifdef USE_PGP
		status = queryPgpObject( &stream, &queryInfo );
#else
		status = CRYPT_ERROR_BADDATA;
#endif /* USE_PGP */
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Copy the externally-visible fields across */
	cryptObjectInfo->objectType = queryInfo.type;
	cryptObjectInfo->cryptAlgo = queryInfo.cryptAlgo;
	cryptObjectInfo->cryptMode = queryInfo.cryptMode;
	if( queryInfo.type == CRYPT_OBJECT_SIGNATURE )
		cryptObjectInfo->hashAlgo = queryInfo.hashAlgo;
	if( queryInfo.type == CRYPT_OBJECT_ENCRYPTED_KEY && \
		queryInfo.saltLength > 0 )
		{
		memcpy( cryptObjectInfo->salt, queryInfo.salt, queryInfo.saltLength );
		cryptObjectInfo->saltSize = queryInfo.saltLength;
		}

	return( CRYPT_OK );
	}
