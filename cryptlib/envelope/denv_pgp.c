/****************************************************************************
*																			*
*					 cryptlib PGP De-enveloping Routines					*
*					 Copyright Peter Gutmann 1996-2002						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "envelope.h"
  #include "pgp.h"
  #include "misc_rw.h"
  #include "objinfo.h"
#elif defined( INC_CHILD )
  #include "envelope.h"
  #include "pgp.h"
  #include "../misc/misc_rw.h"
  #include "../misc/objinfo.h"
#else
  #include "envelope/envelope.h"
  #include "envelope/pgp.h"
  #include "misc/misc_rw.h"
  #include "misc/objinfo.h"
#endif /* Compiler-specific includes */

#ifdef USE_PGP

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get information on a PGP data packet */

static int getPacketInfo( STREAM *stream, ENVELOPE_INFO *envelopeInfoPtr,
						  long *length )
	{
	int ctb, status;

	/* Read the packet header and extract information from the CTB.  Note 
	   that the assignment of version numbers is speculative only, since 
	   it's possible to use PGP 2.x packet headers to wrap up OpenPGP 
	   packets */
	status = pgpReadPacketHeader( stream, &ctb, length );
	if( cryptStatusError( status ) )
		return( status );
	if( ( ctb & PGP_CTB_OPENPGP ) == PGP_CTB_OPENPGP )
		envelopeInfoPtr->version = PGP_VERSION_OPENPGP;
	else
		envelopeInfoPtr->version = PGP_VERSION_2;

	/* Extract and return the packet type */
	return( ( ( ctb & PGP_CTB_OPENPGP ) == PGP_CTB_OPENPGP ) ? \
			( ctb & 0x3F ) : ( ( ctb >> 2 ) & 0x0F ) );
	}

/****************************************************************************
*																			*
*						Read Key Exchange/Signature Packets					*
*																			*
****************************************************************************/

/* Add information about an object to an envelope's content information list */

static int addContentListItem( STREAM *stream,
							   ENVELOPE_INFO *envelopeInfoPtr,
							   const BOOLEAN isContinuedSignature )
	{
	QUERY_INFO queryInfo;
	CONTENT_LIST *contentListItem;
	void *object = NULL, *originalObjectPtr;
	int status;

	/* PGP 2.x password-encrypted data is detected by the absence of any
	   other keying object rather than by finding a concrete object type, so
	   if we're passed a null stream we add a password pseudo-object */
	if( stream == NULL )
		{
		CONTENT_ENCR_INFO *encrInfo;

		contentListItem = createContentListItem( envelopeInfoPtr->memPoolState,
												 CRYPT_FORMAT_PGP, NULL, 0, 
												 FALSE );
		if( contentListItem == NULL )
			return( CRYPT_ERROR_MEMORY );
		encrInfo = &contentListItem->clEncrInfo;
		contentListItem->envInfo = CRYPT_ENVINFO_PASSWORD;
		encrInfo->cryptAlgo = CRYPT_ALGO_IDEA;
		encrInfo->cryptMode = CRYPT_MODE_CFB;
		encrInfo->keySetupAlgo = CRYPT_ALGO_MD5;
		appendContentListItem( envelopeInfoPtr, contentListItem );
		return( CRYPT_OK );
		}

	/* Find the size of the object, allocate a buffer for it if necessary,
	   and copy it across */
	originalObjectPtr = sMemBufPtr( stream );
	status = queryPgpObject( stream, &queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( queryInfo.type == CRYPT_OBJECT_SIGNATURE && \
		queryInfo.dataStart == NULL )
		{
		/* It's a one-pass signature packet, the signature information 
		   follows in another packet that will be added later */
		sSkip( stream, ( int ) queryInfo.size );
		queryInfo.size = 0;
		}
	else
		{
		if( ( object = clAlloc( "addContentListItem", \
								( size_t ) queryInfo.size ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		sread( stream, object, ( int ) queryInfo.size );
		}

	/* If it's the rest of the signature data from a one-pass signature,
	   locate the first half of the signature info and complete the
	   information.  In theory this could get ugly because there could be
	   multiple one-pass signature packets present, however PGP handles
	   multiple signatures by nesting them so this isn't a problem */
	if( isContinuedSignature )
		{
		for( contentListItem = envelopeInfoPtr->contentList;
			 contentListItem != NULL && \
				contentListItem->envInfo != CRYPT_ENVINFO_SIGNATURE;
			 contentListItem = contentListItem->next );
		assert( contentListItem->object == NULL && \
				contentListItem->objectSize == 0 );
		contentListItem->object = object;
		contentListItem->objectSize = ( int ) queryInfo.size;
		}
	else
		{
		/* Allocate memory for the new content list item and copy information
		   on the item across */
		contentListItem = createContentListItem( envelopeInfoPtr->memPoolState,
									CRYPT_FORMAT_PGP, object,
									( int ) queryInfo.size,
									queryInfo.type == CRYPT_OBJECT_SIGNATURE );
		if( contentListItem == NULL )
			{
			if( object != NULL )
				clFree( "addContentListItem", object );
			return( CRYPT_ERROR_MEMORY );
			}
		}
	if( queryInfo.type == CRYPT_OBJECT_PKCENCRYPTED_KEY || \
		queryInfo.type == CRYPT_OBJECT_SIGNATURE )
		{
		/* Remember details of the enveloping info that we require to 
		   continue.  Note that if we're processing a one-pass signature 
		   packet followed by signature data, the keyID and algorithm info
		   in the signature packet takes precendence in case of 
		   inconsistencies between the two */
		if( queryInfo.type == CRYPT_OBJECT_PKCENCRYPTED_KEY )
			{
			CONTENT_ENCR_INFO *encrInfo = &contentListItem->clEncrInfo;

			contentListItem->envInfo = CRYPT_ENVINFO_PRIVATEKEY;
			encrInfo->cryptAlgo = queryInfo.cryptAlgo;
			}
		else
			{
			CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;

			contentListItem->envInfo = CRYPT_ENVINFO_SIGNATURE;
			sigInfo->hashAlgo = queryInfo.hashAlgo;
			if( queryInfo.attributeStart != NULL )
				{
				sigInfo->extraData = \
					( BYTE * ) contentListItem->object + \
					( ( BYTE * ) queryInfo.attributeStart - ( BYTE * ) originalObjectPtr );
				sigInfo->extraDataLength = queryInfo.attributeLength;
				}
			if( queryInfo.unauthAttributeStart != NULL )
				{
				sigInfo->extraData2 = \
					( BYTE * ) contentListItem->object + \
					( ( BYTE * ) queryInfo.unauthAttributeStart - ( BYTE * ) originalObjectPtr );
				sigInfo->extraData2Length = queryInfo.unauthAttributeLength;
				}
			}
		memcpy( contentListItem->keyID, queryInfo.keyID, 
				queryInfo.keyIDlength );
		contentListItem->keyIDsize = queryInfo.keyIDlength;
		if( queryInfo.iAndSStart != NULL )
			{
			contentListItem->issuerAndSerialNumber = \
					( BYTE * ) contentListItem->object + \
					( ( BYTE * ) queryInfo.iAndSStart - ( BYTE * ) originalObjectPtr );
			contentListItem->issuerAndSerialNumberSize = queryInfo.iAndSLength;
			}
		}
	if( queryInfo.type == CRYPT_OBJECT_ENCRYPTED_KEY )
		{
		CONTENT_ENCR_INFO *encrInfo = &contentListItem->clEncrInfo;

		/* Remember details of the enveloping info that we require to 
		   continue */
		if( queryInfo.keySetupAlgo != CRYPT_ALGO_NONE )
			{
			contentListItem->envInfo = CRYPT_ENVINFO_PASSWORD;
			encrInfo->keySetupAlgo = queryInfo.keySetupAlgo;
			encrInfo->keySetupIterations = queryInfo.keySetupIterations;
			memcpy( encrInfo->saltOrIV, queryInfo.salt, 
					queryInfo.saltLength );
			encrInfo->saltOrIVsize = queryInfo.saltLength;
			}
		else
			contentListItem->envInfo = CRYPT_ENVINFO_KEY;
		encrInfo->cryptAlgo = queryInfo.cryptAlgo;
		encrInfo->cryptMode = CRYPT_MODE_CFB;
		}
	if( queryInfo.dataStart != NULL )
		{
		contentListItem->payload = \
					( BYTE * ) contentListItem->object + \
					( ( BYTE * ) queryInfo.dataStart - ( BYTE * ) originalObjectPtr );
		contentListItem->payloadSize = queryInfo.dataLength;
		}
	if( queryInfo.version > envelopeInfoPtr->version )
		envelopeInfoPtr->version = queryInfo.version;

	/* If we're completing the read of the data in a one-pass signature
	   packet, we're done */
	if( isContinuedSignature )
		return( CRYPT_OK );

	/* If it's signed data, create a hash action to process it */
	if( queryInfo.type == CRYPT_OBJECT_SIGNATURE )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Append a new hash action to the action list */
		setMessageCreateObjectInfo( &createInfo,
									contentListItem->clSigInfo.hashAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) && \
			addAction( &envelopeInfoPtr->actionList, 
					   envelopeInfoPtr->memPoolState, ACTION_HASH,
					   createInfo.cryptHandle ) == NULL )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			status = CRYPT_ERROR_MEMORY;
			}
		if( cryptStatusError( status ) )
			{
			deleteContentList( envelopeInfoPtr->memPoolState, 
							   contentListItem );
			return( status );
			}
		}
	appendContentListItem( envelopeInfoPtr, contentListItem );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Process Envelope Preamble/Postamble					*
*																			*
****************************************************************************/

/* Process the non-data portions of a PGP message.  This is a complex event-
   driven state machine, but instead of reading along a (hypothetical
   Turing-machine) tape, someone has taken the tape and cut it into bits and
   keeps feeding them to us and saying "See what you can do with this" (and
   occasionally "Where's the bloody spoons?").  Since PGP uses sequential
   discrete packets rather than the nested objects encountered in the ASN.1-
   encoded data format, the parsing code is made somewhat simpler because
   (for example) the PKC info is just an unconnected sequence of packets
   rather than a SEQUENCE or SET OF as for cryptlib and PKCS #7.  OTOH since
   there's no indication of what's next we have to perform a complex
   lookahead to see what actions we have to take once we get to the payload */

static int processPreamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	PGP_DEENV_STATE state = envelopeInfoPtr->pgpDeenvState;
	STREAM stream;
	int packetType, length, streamPos = 0, status = CRYPT_OK;
	long packetLength;

	/* If we've finished processing the start of the message, header, don't
	   do anything */
	if( state == PGP_DEENVSTATE_DONE )
		return( CRYPT_OK );

	sMemConnect( &stream, envelopeInfoPtr->buffer, envelopeInfoPtr->bufPos );

	/* Keep consuming information until we run out of input or reach the
	   plaintext data packet */
	while( state != PGP_DEENVSTATE_DONE )
		{
		/* Read the PGP packet type and figure out what we've got */
		if( state == PGP_DEENVSTATE_NONE )
			{
			int value;

			streamPos = stell( &stream );
			packetType = getPacketInfo( &stream, envelopeInfoPtr, &packetLength );
			if( cryptStatusError( packetType ) )
				return( packetType );

			/* Process as much of the header as we can and move on to the next
			   state.  Since PGP uses sequential discrete packets, for any
			   of the non-payload packet types we stay in the "none" state
			   because we don't know what's next */
			switch( packetType )
				{
				case PGP_PACKET_DATA:
					/* Skip the content-type, filename, and date */
					sSkip( &stream, 1 );
					length = sgetc( &stream );
					if( !cryptStatusError( length ) )
						sSkip( &stream, length + 4 );
					status = sGetStatus( &stream );
					if( cryptStatusError( status ) )
						break;

					/* Remember where we are and move on to the next state */
					envelopeInfoPtr->payloadSize = packetLength - \
												   ( 1 + 1 + length + 4 );
					if( envelopeInfoPtr->payloadSize < 1 )
						{
						status = CRYPT_ERROR_BADDATA;
						break;
						}
					state = PGP_DEENVSTATE_DATA;
					break;

				case PGP_PACKET_COPR:
					value = sgetc( &stream );
					if( envelopeInfoPtr->usage != ACTION_NONE )
						{
						status = CRYPT_ERROR_BADDATA;
						break;
						}
					envelopeInfoPtr->usage = ACTION_COMPRESS;
#ifdef USE_COMPRESSION
					if( value == PGP_ALGO_ZIP )
						{
						/* PGP 2.x has a funny compression level based on DOS
						   memory limits (13-bit windows) and no zlib header
						   (because it uses very old InfoZIP code).  Setting
						   the windowSize to a negative value has the
						   undocumented effect of not reading zlib headers */
						if( inflateInit2( &envelopeInfoPtr->zStream, -13 ) == Z_OK )
							envelopeInfoPtr->flags |= ENVELOPE_ZSTREAMINITED;
						else
							status = CRYPT_ERROR_MEMORY;
						}
					else
						if( value == PGP_ALGO_ZLIB )
							{
							/* Standard zlib compression */
							if( inflateInit( &envelopeInfoPtr->zStream ) == Z_OK )
								envelopeInfoPtr->flags |= ENVELOPE_ZSTREAMINITED;
							else
								status = CRYPT_ERROR_MEMORY;
							}
						else
							{
							status = ( value < 0 ) ? \
									 value : CRYPT_ERROR_NOTAVAIL;
							break;
							}
#else
					status = CRYPT_ERROR_NOTAVAIL;
#endif /* USE_COMPRESSION */
					state = PGP_DEENVSTATE_DATA;
					break;

				case PGP_PACKET_SKE:
				case PGP_PACKET_PKE:
					/* Read the SKE/PKE packet */
					if( envelopeInfoPtr->usage != ACTION_NONE && \
						envelopeInfoPtr->usage != ACTION_CRYPT )
						{
						status = CRYPT_ERROR_BADDATA;
						break;
						}
					envelopeInfoPtr->usage = ACTION_CRYPT;
					sseek( &stream, streamPos );
					status = addContentListItem( &stream, envelopeInfoPtr, 
												 FALSE );
					break;

				case PGP_PACKET_SIGNATURE:
				case PGP_PACKET_SIGNATURE_ONEPASS:
					/* Try and guess whether this is a standalone signature.
					   This is rather difficult since, unlike S/MIME, there's
					   no way to tell whether a PGP signature packet is part
					   of other data or standalone.  The best we can do is
					   assume that if the caller added a hash action and we
					   find a signature, it's a detached signature.
					   Unfortunately there's no way to tell whether a
					   signature packet with no user-supplied hash is a
					   standalone signature or the start of further signed
					   data, so we can't handle detached signatures where the
					   user doesn't supply the hash */
					if( envelopeInfoPtr->usage == ACTION_SIGN && \
						envelopeInfoPtr->actionList != NULL && \
						envelopeInfoPtr->actionList->action == ACTION_HASH )
						{
						/* We can't have a detached sig packet as a one-pass
						   sig */
						if( packetType == PGP_PACKET_SIGNATURE_ONEPASS )
							{
							status = CRYPT_ERROR_BADDATA;
							break;
							}
						envelopeInfoPtr->flags |= ENVELOPE_DETACHED_SIG;
						}

					/* Read the signature/signature information packet.  We
					   allow the usage to be set already if we find a
					   signature packet since it could have been preceded by
					   a one-pass signature packet or be a detached
					   signature */
					if( envelopeInfoPtr->usage != ACTION_NONE && \
						!( packetType == PGP_PACKET_SIGNATURE && \
						   envelopeInfoPtr->usage == ACTION_SIGN ) )
						{
						status = CRYPT_ERROR_BADDATA;
						break;
						}
					envelopeInfoPtr->usage = ACTION_SIGN;
					sseek( &stream, streamPos );
					status = addContentListItem( &stream, envelopeInfoPtr,
												 FALSE );
					if( cryptStatusError( status ) )
						break;
					if( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG )
						{
						/* If it's a one-pass sig, there's no payload
						   present, we can go straight to the postdata
						   state */
						envelopeInfoPtr->dataFlags |= ENVDATA_HASHACTIONSACTIVE;
						envelopeInfoPtr->payloadSize = 0;
						state = PGP_DEENVSTATE_DONE;
						}
					else
						state = PGP_DEENVSTATE_DATA;
					break;

				case PGP_PACKET_ENCR_MDC:
					/* The encrypted-data-with-MDC packet is preceded by a
					   version number */
					status = sgetc( &stream );
					if( !cryptStatusError( status ) && status != 1 )
						status = CRYPT_ERROR_BADDATA;
					if( cryptStatusError( status ) )
						break;
					packetLength--;
					/* Fall through */

				case PGP_PACKET_ENCR:
					if( envelopeInfoPtr->usage != ACTION_NONE && \
						envelopeInfoPtr->usage != ACTION_CRYPT )
						{
						status = CRYPT_ERROR_BADDATA;
						break;
						}

					/* Remember the packet length in case the inner packet
					   uses an indefinite-length encoding */
					if( packetLength != CRYPT_UNUSED )
						envelopeInfoPtr->payloadSize = packetLength;
					envelopeInfoPtr->usage = ACTION_CRYPT;
					state = ( packetType == PGP_PACKET_ENCR_MDC ) ? \
							PGP_DEENVSTATE_ENCR_MDC : PGP_DEENVSTATE_ENCR;
					break;

				case PGP_PACKET_MARKER:
					/* Obsolete marker packet, skip it */
					status = sSkip( &stream, packetLength );
					break;

				default:
					status = CRYPT_ERROR_BADDATA;
				}

			/* If there's a problem, exit */
			if( cryptStatusError( status ) )
				break;

			/* Remember how far we got */
			streamPos = stell( &stream );
			}

		/* Process the start of an encrypted data packet */
		if( state == PGP_DEENVSTATE_ENCR || \
			state == PGP_DEENVSTATE_ENCR_MDC )
			{
			BYTE ivInfoBuffer[ CRYPT_MAX_IVSIZE + 2 ];
			int ivSize;

			/* If there aren't any non-session-key keying resource objects
			   present, we can't go any further until we get a session key */
			if( envelopeInfoPtr->actionList == NULL )
				{
				/* There's no session key object present, add a pseudo-object
				   that takes the place of the (password-derived) session key
				   object in the content list.  This can only occur for PGP
				   2.x conventionally-encrypted data, which didn't encode any
				   algorithm information with the data, so if we get to this
				   point we know we've hit data encrypted with the default
				   IDEA/CFB derived from a user password using MD5 */
				if( envelopeInfoPtr->contentList == NULL )
					{
					status = addContentListItem( NULL, envelopeInfoPtr, FALSE );
					if( cryptStatusError( status ) )
						break;
					}

				/* We can't continue until we're given some sort of keying
				   resource */
				status = CRYPT_ENVELOPE_RESOURCE;
				break;
				}
			assert( envelopeInfoPtr->actionList->action == ACTION_CRYPT );

			/* Read and process PGP's peculiar two-stage IV */
			status = krnlSendMessage( envelopeInfoPtr->actionList->iCryptHandle,
									  IMESSAGE_GETATTRIBUTE, &ivSize, 
									  CRYPT_CTXINFO_IVSIZE );
			if( cryptStatusOK( status ) )
				status = sread( &stream, ivInfoBuffer, ivSize + 2 );
			if( !cryptStatusError( status ) )
				status = pgpProcessIV( envelopeInfoPtr->actionList->iCryptHandle,
									   ivInfoBuffer, ivSize, FALSE,
									   ( state == PGP_DEENVSTATE_ENCR ) ? \
										 TRUE : FALSE );
			if( cryptStatusError( status ) )
				break;
			envelopeInfoPtr->iCryptContext = \
								envelopeInfoPtr->actionList->iCryptHandle;

			/* If we're keeping track of the outer packet size in case
			   there's no inner size info present, adjust it by the data
			   we've just processed and any other data that may be
			   present */
			if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
				{
				envelopeInfoPtr->payloadSize -= stell( &stream );
				if( state == PGP_DEENVSTATE_ENCR_MDC )
					/* There was a bug in all versions of GPG before 1.0.8,
					   which omitted the MDC packet length when a packet was
					   encrypted without compression.  As a result, 
					   uncompressed messages generated by this version can't
					   be processed */
					envelopeInfoPtr->payloadSize -= PGP_MDC_PACKET_SIZE;
				}

			/* If there's an MDC packet present, prepare to hash the payload
			   data */
			if( state == PGP_DEENVSTATE_ENCR_MDC )
				{
				MESSAGE_CREATEOBJECT_INFO createInfo;

				/* Append a hash action to the action list */
				setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
				status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
										  IMESSAGE_DEV_CREATEOBJECT,
										  &createInfo, OBJECT_TYPE_CONTEXT );
				if( cryptStatusError( status ) )
					break;
				if( addAction( &envelopeInfoPtr->actionList, 
							   envelopeInfoPtr->memPoolState, ACTION_HASH,
							   createInfo.cryptHandle ) == NULL )
					{
					krnlSendNotifier( createInfo.cryptHandle,
									  IMESSAGE_DECREFCOUNT );
					status = CRYPT_ERROR_MEMORY;
					break;
					}
				envelopeInfoPtr->dataFlags |= ENVDATA_HASHACTIONSACTIVE;
				}

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			state = PGP_DEENVSTATE_DATA;
			}

		/* Process the start of a data packet */
		if( state == PGP_DEENVSTATE_DATA )
			{
			/* Synchronise the data stream processing to the start of the
			   encrypted data and move back to the start of the data
			   stream */
			status = envelopeInfoPtr->syncDeenvelopeData( envelopeInfoPtr,
														  &stream );
			if( cryptStatusError( status ) )
				break;
			streamPos = 0;
			assert( actionsOK( envelopeInfoPtr ) );

			/* Move on to the next state.  For plain data we're done,
			   however for other content types we have to either process or
			   strip out the junk PGP puts at the start of the content */
			if( envelopeInfoPtr->usage != ACTION_NONE )
				{
				envelopeInfoPtr->oobEventCount = 1;
				state = PGP_DEENVSTATE_DATA_HEADER;
				}
			else
				state = PGP_DEENVSTATE_DONE;
			assert( actionsOK( envelopeInfoPtr ) );
			}

		/* PGP doesn't provide any indication of what the content of the
		   current packet is, so we have to burrow down into the encrypted
		   data to see whether the payload needs any further processing.
		   This state looks ahead into this data to see whether we need to
		   strip the header (for a plain data packet) or inform the user
		   that there's a nested content type */
		if( state == PGP_DEENVSTATE_DATA_HEADER )
			{
			STREAM headerStream;
			BYTE buffer[ 64 + 256 ];
			int bytesWanted;

			/* If there's no out-of-band data left to remove at the start of
			   the payload, we're done */
			if( !envelopeInfoPtr->oobEventCount && \
				!envelopeInfoPtr->oobDataLeft )
				break;

			/* We have to perform all sorts of special-case processing to
			   handle the out-of-band packet header at the start of the
			   payload.  Initially, we need to find out how much header data
			   is actually present.  The header consists of:
				byte	ctb
				byte[]	length
				byte	type = 'b' | 't'
				byte	filename length
				byte[]	filename
				byte[4]	timestamp

			   The smallest size for this header (1-byte length, no filename)
			   is 1 + 1 + 1 + 1 + 4 = 8 bytes.  This is also just enough to
			   get us to the filename length for a maximum-size header, which
			   is 1 + 5 + 1 + 1 bytes up to the filename length.  Thus we
			   read 8 bytes */
			bytesWanted = envelopeInfoPtr->oobEventCount ? \
						  -8 : envelopeInfoPtr->oobDataLeft;

			/* Try and read the the requested amount of out-of-band data
			   from the start of the payload */
			length = envelopeInfoPtr->copyFromEnvelopeFunction( envelopeInfoPtr,
														buffer, bytesWanted );
			if( cryptStatusError( length ) )
				status = length;
			else
				if( length < \
					( ( bytesWanted >= 0 ) ? bytesWanted : -bytesWanted ) )
					status = CRYPT_ERROR_UNDERFLOW;
			if( cryptStatusError( status ) )
				break;

			/* If we're down to stripping raw header data, clean up and
			   exit */
			if( !envelopeInfoPtr->oobEventCount )
				{
				/* We've successfully stripped all the out-of-band data.  If
				   it's compressed data (which doesn't have a 1:1
				   correspondence between input and output and that has an
				   unknown-length encoding so there's no length information
				   to adjust), exit */
				envelopeInfoPtr->oobDataLeft = 0;
				if( envelopeInfoPtr->usage == ACTION_COMPRESS )
					{
					state = PGP_DEENVSTATE_DONE;
					continue;
					}

				/* Adjust the current data count by what we've removed.  If
				   we've reached the end of the data (i.e. the entire current
				   segment is contained within the data present in the
				   buffer), remember that what's left still needs to be
				   processed (e.g. hashed in the case of signed data) on the
				   way out */
				envelopeInfoPtr->segmentSize -= length;
				assert( envelopeInfoPtr->segmentSize >= 0 );
				if( envelopeInfoPtr->segmentSize <= envelopeInfoPtr->bufPos )
					{
					envelopeInfoPtr->dataLeft = envelopeInfoPtr->segmentSize;
					envelopeInfoPtr->segmentSize = 0;
					}

				/* We've processed the header, if this is signed data we
				   start hashing from this point (the PGP RFCs are wrong in
				   this regard, only the payload is hashed, not the entire
				   packet) */
				if( envelopeInfoPtr->usage == ACTION_SIGN )
					envelopeInfoPtr->dataFlags |= ENVDATA_HASHACTIONSACTIVE;

				/* We're done */
				state = PGP_DEENVSTATE_DONE;
				continue;
				}

			/* Read the header information and see what we've got */
			sMemConnect( &headerStream, buffer, length );
			packetType = getPacketInfo( &headerStream, envelopeInfoPtr,
										&packetLength );
			if( cryptStatusError( packetType ) )
				{
				sMemClose( &headerStream );
				status = packetType;
				break;
				}

			/* Remember the total data packet size unless it's compressed
			   data, which doesn't have a 1:1 correspondence between input
			   and output */
			if( envelopeInfoPtr->usage != ACTION_COMPRESS )
				{
				/* If it's a definite-length packet, use the overall packet
				   size.  This also skips any MDC packets that may be
				   attached to the end of the plaintext */
				if( packetLength != CRYPT_UNUSED )
					envelopeInfoPtr->payloadSize = \
									envelopeInfoPtr->segmentSize = \
									stell( &headerStream ) + packetLength;
				else
					/* It's an indefinite-length packet, if we got length
					   information earlier from the outer packet use that */
					if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
						envelopeInfoPtr->segmentSize = \
									envelopeInfoPtr->payloadSize;
					else
						{
						/* Both the outer and inner packets are indefinite-
						   length, we can't process the data because we don't
						   know its length */
						sMemClose( &headerStream );
						status = CRYPT_ERROR_BADDATA;
						break;
						}
				}

			/* If it's a literal data packet, parse it so that we can strip 
			   it from the data that we return to the caller */
			if( packetType == PGP_PACKET_DATA )
				{
				int extraLen;

				sgetc( &headerStream );		/* Skip content type */
				extraLen = sgetc( &headerStream );
				envelopeInfoPtr->oobDataLeft = stell( &headerStream ) + \
											   extraLen + 4;
				sMemDisconnect( &headerStream );

				/* We've processed enough of the header to know what to do
				   next, move on to the next stage where we just consume all
				   the input */
				envelopeInfoPtr->oobEventCount--;
				}
			else
				{
				static const struct {
					const int pgpType; const int cryptlibType;
					} typeMapTbl[] = {
					{ PGP_PACKET_COPR, CRYPT_CONTENT_COMPRESSEDDATA },
					{ PGP_PACKET_ENCR, CRYPT_CONTENT_ENCRYPTEDDATA },
					{ PGP_PACKET_ENCR_MDC, CRYPT_CONTENT_ENCRYPTEDDATA },
					{ PGP_PACKET_SKE, CRYPT_CONTENT_ENCRYPTEDDATA },
					{ PGP_PACKET_PKE, CRYPT_CONTENT_ENVELOPEDDATA },
					{ PGP_PACKET_SIGNATURE, CRYPT_CONTENT_SIGNEDDATA },
					{ PGP_PACKET_SIGNATURE_ONEPASS, CRYPT_CONTENT_SIGNEDDATA },
					{ CRYPT_ERROR, CRYPT_ERROR },
					};
				int i;

				sMemDisconnect( &headerStream );

				/* If it's a known packet type, indicate it as the nested
				   content type */
				for( i = 0; typeMapTbl[ i ].pgpType != CRYPT_ERROR; i++ )
					if( typeMapTbl[ i ].pgpType == packetType )
						{
						envelopeInfoPtr->contentType = \
											typeMapTbl[ i ].cryptlibType;
						break;
						}
				if( typeMapTbl[ i ].pgpType == CRYPT_ERROR )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}

				/* If it's not compressed data (which doesn't have a 1:1
				   correspondence between input and output), we've reached
				   the end of the data (i.e. the entire current segment is
				   contained within the data present in the buffer), remember
				   that what's left still needs to be processed (e.g. hashed
				   in the case of signed data) on the way out */
				if( envelopeInfoPtr->usage != ACTION_COMPRESS && \
					envelopeInfoPtr->segmentSize <= envelopeInfoPtr->bufPos )
					{
					envelopeInfoPtr->dataLeft = envelopeInfoPtr->segmentSize;
					envelopeInfoPtr->segmentSize = 0;
					}

				/* Don't try and process the content any further */
				envelopeInfoPtr->oobEventCount = \
								envelopeInfoPtr->oobDataLeft = 0;
				state = PGP_DEENVSTATE_DONE;
				}
			}
		}
	envelopeInfoPtr->pgpDeenvState = state;

	assert( streamPos >= 0 && envelopeInfoPtr->bufPos - streamPos >= 0 );

	/* Consume the input we've processed so far by moving everything past the
	   current position down to the start of the envelope buffer */
	length = envelopeInfoPtr->bufPos - streamPos;
	if( length > 0 && streamPos > 0 )
		memmove( envelopeInfoPtr->buffer, envelopeInfoPtr->buffer + streamPos,
				length );
	envelopeInfoPtr->bufPos = length;

	/* If all went OK but we're still not out of the header information,
	   return an underflow error */
	if( cryptStatusOK( status ) && state != PGP_DEENVSTATE_DONE )
		status = CRYPT_ERROR_UNDERFLOW;

	/* Clean up */
	sMemDisconnect( &stream );
	return( status );
	}

static int processPostamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	CONTENT_LIST *contentListPtr;
	const BOOLEAN hasMDC = \
			( envelopeInfoPtr->usage == ACTION_CRYPT && \
			  ( envelopeInfoPtr->dataFlags & ENVDATA_HASHACTIONSACTIVE ) ) ? \
			TRUE : FALSE;
	int status = CRYPT_OK;

	/* If that's all there is, return */
	if( envelopeInfoPtr->usage != ACTION_SIGN && !hasMDC )
		return( CRYPT_OK );

	/* If there's an MDC packet present, complete the hashing and make sure
	   the integrity check matches */
	if( hasMDC )
		{
		/* Make sure that there's enough data left in the stream to obtain 
		   the MDC info, and get the MDC packet */
		if( envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft < \
			PGP_MDC_PACKET_SIZE )
			return( CRYPT_ERROR_UNDERFLOW );

		/* Processing beyond this point gets rather complex because we have
		   to defer reading the MDC packet until all the remaining data has
		   been popped, while processing reaches this point when data is 
		   pushed.  Conventionally signed/hashed data hashes the plaintext, 
		   so once we reach this point we can wrap up the hashing ready for 
		   the (user-initiated) sig check.  The MDC packet however is still
		   encrypted at this point, along with some or all of the data to be 
		   hashed, which means that we can't do anything yet.  In order to 
		   handle this special-case situation, we'd have to add extra 
		   capabilities to the data-popping code to tell it that after a 
		   certain amount of data has been popped, what's still left is MDC
		   data.  This severely screws up the layering, since the 
		   functionality is neither at the cryptenv.c level nor at the 
		   env_dec.c level, and represents an approach that was abandoned in
		   cryptlib 2.1 when it proved impossible to get it working reliably
		   under all circumstances (it's provably impossible to do with ASN.1
		   variable-length length encoding where changing data by one byte
		   can result in a variable change of length for inner lengths, 
		   making it impossible to encode some data lengths to the fixed size 
		   required by a CBC-mode cipher).  This is why cryptlib uses 
		   separate passes for each processing layer rather than trying to 
		   combine encryption and signing into a single pass.

		   Because of this, handling of MDC packets is only done if all the
		   data in the envelope has been popped (but see the note below), 
		   fully general handling won't be added unless there is sufficient 
		   user demand to justify messing up the architectural layering of 
		   the enveloping code.  Note that this situation can never occur 
		   (since we're being called when data is pushed, so bufPos will 
		   never be zero), the following code is present only as a 
		   representative example */
		if( envelopeInfoPtr->dataLeft == PGP_MDC_PACKET_SIZE )
			{
			BYTE buffer[ PGP_MDC_PACKET_SIZE ];

			envelopeInfoPtr->copyFromEnvelopeFunction( envelopeInfoPtr, 
											buffer, PGP_MDC_PACKET_SIZE );
			if( buffer[ 0 ] != 0xD0 || buffer[ 1 ] != 0x14 )
				return( CRYPT_ERROR_BADDATA );

			/* Hash the trailer bytes (the start of the MDC packet) and wrap 
			   up the hashing */
			envelopeInfoPtr->processExtraData( envelopeInfoPtr, buffer + 2,
											   PGP_MDC_PACKET_SIZE - 2 );
			status = envelopeInfoPtr->processExtraData( envelopeInfoPtr, 
														"", 0 );
			if( cryptStatusError( status ) )
				return( status );
			}
		return( CRYPT_OK );
		}

	/* Find the signature information in the content list.  In theory this
	   could get ugly because there could be multiple one-pass signature
	   packets present, however PGP handles multiple signatures by nesting
	   them so this isn't a problem */
	for( contentListPtr = envelopeInfoPtr->contentList;
		 contentListPtr != NULL && \
			contentListPtr->envInfo != CRYPT_ENVINFO_SIGNATURE;
		 contentListPtr = contentListPtr->next );

	/* PGP 2.x prepended (!!) signatures to the signed data, OpenPGP fixed 
	   this by splitting the signature into a header with signature info and 
	   a trailer with the actual signature.  If we're processing a PGP 2.x
	   signature, we'll already have the signature data present, so we only
	   check for signature data if it's not already available */
	if( contentListPtr->object == NULL )
		{
		STREAM stream;
		long packetLength;
		int packetType;

		/* Make sure that there's enough data left in the stream to do 
		   something with.  This isn't strictly necessary for the following 
		   code to work but is required to avoid triggering the zero-length 
		   stream check */
		if( envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft < \
			PGP_MAX_HEADER_SIZE )
			return( CRYPT_ERROR_UNDERFLOW );

		/* Read the signature packet at the end of the payload */
		sMemConnect( &stream, envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
					 envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft );
		packetType = getPacketInfo( &stream, envelopeInfoPtr, &packetLength );
		if( !cryptStatusError( packetType ) && \
			packetType != PGP_PACKET_SIGNATURE )
			packetType = CRYPT_ERROR_BADDATA;
		if( cryptStatusError( packetType ) )
			{
			sMemDisconnect( &stream );
			return( packetType );
			}
		sseek( &stream, 0 );
		status = addContentListItem( &stream, envelopeInfoPtr, TRUE );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* When we reach this point there may still be unhashed data left in the 
	   buffer (it won't have been hashed yet because the hashing is performed 
	   when the data is copied out, after unwrapping and whatnot) so we hash 
	   it before we exit.  Since we don't wrap up the hashing as we do with
	   any other format (PGP hashes in all sorts of odds and ends after 
	   hashing the message body), we have to manually turn off hashing here */
	if( envelopeInfoPtr->dataLeft > 0 )
		status = envelopeInfoPtr->processExtraData( envelopeInfoPtr,
						envelopeInfoPtr->buffer, envelopeInfoPtr->dataLeft );
	envelopeInfoPtr->dataFlags &= ~ENVDATA_HASHACTIONSACTIVE;
	return( status );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

void initPGPDeenveloping( ENVELOPE_INFO *envelopeInfoPtr )
	{
	/* Set the access method pointers */
	envelopeInfoPtr->processPreambleFunction = processPreamble;
	envelopeInfoPtr->processPostambleFunction = processPostamble;

	/* Set up the processing state information */
	envelopeInfoPtr->pgpDeenvState = PGP_DEENVSTATE_NONE;
	}
#endif /* USE_PGP */
