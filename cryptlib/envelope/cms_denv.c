/****************************************************************************
*																			*
*					  cryptlib De-enveloping Routines						*
*					 Copyright Peter Gutmann 1996-2005						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "envelope.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#elif defined( INC_CHILD )
  #include "envelope.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
#else
  #include "envelope/envelope.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_ENVELOPES

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* OID information used to read enveloped data */

static const FAR_BSS CMS_CONTENT_INFO oidInfoSignedData = { 0, 3 };
static const FAR_BSS CMS_CONTENT_INFO oidInfoEnvelopedData = { 0, 2 };
static const FAR_BSS CMS_CONTENT_INFO oidInfoDigestedData = { 0, 2 };
static const FAR_BSS CMS_CONTENT_INFO oidInfoEncryptedData = { 0, 2 };
static const FAR_BSS CMS_CONTENT_INFO oidInfoCompressedData = { 0, 0 };
static const FAR_BSS OID_INFO envelopeOIDinfo[] = {
	{ OID_CMS_DATA, ACTION_NONE },
	{ OID_CMS_SIGNEDDATA, ACTION_SIGN, &oidInfoSignedData },
	{ OID_CMS_ENVELOPEDDATA, ACTION_KEYEXCHANGE, &oidInfoEnvelopedData },
	{ OID_CMS_DIGESTEDDATA, ACTION_HASH, &oidInfoDigestedData },
	{ OID_CMS_ENCRYPTEDDATA, ACTION_CRYPT, &oidInfoEncryptedData },
	{ OID_CMS_COMPRESSEDDATA, ACTION_COMPRESS, &oidInfoCompressedData },
	{ OID_CMS_TSTOKEN, ACTION_NONE },
	{ OID_MS_SPCINDIRECTDATACONTEXT, ACTION_NONE },
	{ OID_CRYPTLIB_RTCSREQ, ACTION_NONE },
	{ OID_CRYPTLIB_RTCSRESP, ACTION_NONE },
	{ OID_CRYPTLIB_RTCSRESP_EXT, ACTION_NONE },
	{ NULL, 0 }
	};

static const FAR_BSS OID_INFO nestedContentOIDinfo[] = {
	{ OID_CMS_DATA, CRYPT_CONTENT_DATA },
	{ OID_CMS_SIGNEDDATA, CRYPT_CONTENT_SIGNEDDATA },
	{ OID_CMS_ENVELOPEDDATA, CRYPT_CONTENT_ENVELOPEDDATA },
	{ OID_CMS_ENCRYPTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA },
	{ OID_CMS_TSTOKEN, CRYPT_CONTENT_TSTINFO },
	{ OID_CMS_COMPRESSEDDATA, CRYPT_CONTENT_COMPRESSEDDATA },
	{ OID_MS_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_SPCINDIRECTDATACONTEXT },
	{ OID_CRYPTLIB_RTCSREQ, CRYPT_CONTENT_RTCSREQUEST },
	{ OID_CRYPTLIB_RTCSRESP, CRYPT_CONTENT_RTCSRESPONSE },
	{ OID_CRYPTLIB_RTCSRESP_EXT, CRYPT_CONTENT_RTCSRESPONSE_EXT },
	{ NULL, 0 }
	};

/* Add information about an object to an envelope's content information list */

static int addContentListItem( STREAM *stream, ENVELOPE_INFO *envelopeInfoPtr,
							   QUERY_INFO *externalQueryInfoPtr )
	{
	QUERY_INFO queryInfo, *queryInfoPtr = ( externalQueryInfoPtr == NULL ) ? \
										  &queryInfo : externalQueryInfoPtr;
	CONTENT_LIST *contentListItem;
	void *object = NULL, *originalObjectPtr = sMemBufPtr( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Find the size of the object, allocate a buffer for it, and copy it
	   across */
	if( externalQueryInfoPtr == NULL )
		{
		status = queryAsn1Object( stream, queryInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		if( queryInfoPtr->type == CRYPT_OBJECT_NONE )
			{
			/* It's a valid but unrecognised object type (a new 
			   RecipientInfo type which was added after this version of 
			   cryptlib was released), skip it and continue (if there are no 
			   recognised RecipientInfo types, the code will automatically 
			   fall back to asking the user for a raw session key).  
			   Alternatively, we could just add it to the content list as an 
			   unrecognised object type, but this would lead to confusion 
			   for the caller when non-object-types appear when they query 
			   the current component */
			sSkip( stream, queryInfoPtr->size );
			return( ( int ) queryInfoPtr->size );
			}
		if( ( object = clAlloc( "addContentListItem", \
								( size_t ) queryInfoPtr->size ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		sread( stream, object, ( int ) queryInfoPtr->size );
		}

	/* Allocate memory for the new content list item and copy information on
	   the item across */
	contentListItem = createContentListItem( envelopeInfoPtr->memPoolState,
							queryInfoPtr->formatType, object, 
							( int ) queryInfoPtr->size,
							queryInfoPtr->type == CRYPT_OBJECT_SIGNATURE );
	if( contentListItem == NULL )
		{
		if( externalQueryInfoPtr == NULL )
			clFree( "addContentListItem", object );
		return( CRYPT_ERROR_MEMORY );
		}
	if( externalQueryInfoPtr != NULL )
		{
		CONTENT_ENCR_INFO *encrInfo = &contentListItem->clEncrInfo;

		/* It's externally-supplied crypto algorithm details from an 
		   encrypted data header */
		contentListItem->envInfo = CRYPT_ENVINFO_SESSIONKEY;
		encrInfo->cryptAlgo = queryInfoPtr->cryptAlgo;
		encrInfo->cryptMode = queryInfoPtr->cryptMode;
		memcpy( encrInfo->saltOrIV, queryInfoPtr->iv, queryInfoPtr->ivLength );
		encrInfo->saltOrIVsize = queryInfoPtr->ivLength;
		}
	if( queryInfoPtr->type == CRYPT_OBJECT_PKCENCRYPTED_KEY || \
		queryInfoPtr->type == CRYPT_OBJECT_SIGNATURE )
		{
		/* Remember details of the enveloping info we require to continue */
		if( queryInfoPtr->type == CRYPT_OBJECT_PKCENCRYPTED_KEY )
			contentListItem->envInfo = CRYPT_ENVINFO_PRIVATEKEY;
		else
			{
			contentListItem->envInfo = CRYPT_ENVINFO_SIGNATURE;
			contentListItem->clSigInfo.hashAlgo = queryInfoPtr->hashAlgo;
			}
		if( queryInfoPtr->formatType == CRYPT_FORMAT_CMS )
			{
			contentListItem->issuerAndSerialNumber = \
					( BYTE * ) contentListItem->object + \
					( ( BYTE * ) queryInfoPtr->iAndSStart - \
					  ( BYTE * ) originalObjectPtr );
			contentListItem->issuerAndSerialNumberSize = queryInfoPtr->iAndSLength;
			}
		else
			{
			memcpy( contentListItem->keyID, queryInfoPtr->keyID, 
					queryInfoPtr->keyIDlength );
			contentListItem->keyIDsize = queryInfoPtr->keyIDlength;
			}
		contentListItem->payload = \
					( BYTE * ) contentListItem->object + \
					( ( BYTE * ) queryInfoPtr->dataStart - \
					  ( BYTE * ) originalObjectPtr );
		contentListItem->payloadSize = queryInfoPtr->dataLength;
		if( queryInfoPtr->type == CRYPT_OBJECT_SIGNATURE && \
			queryInfoPtr->formatType == CRYPT_FORMAT_CMS && \
			queryInfoPtr->unauthAttributeStart != NULL )
			{
			CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;

			sigInfo->extraData2 = \
					( BYTE * ) contentListItem->object + \
					( ( BYTE * ) queryInfoPtr->unauthAttributeStart - \
					  ( BYTE * ) originalObjectPtr );
			sigInfo->extraData2Length = queryInfoPtr->unauthAttributeLength;
			}
		}
	if( queryInfoPtr->type == CRYPT_OBJECT_ENCRYPTED_KEY )
		{
		CONTENT_ENCR_INFO *encrInfo = &contentListItem->clEncrInfo;

		/* Remember details of the enveloping info we require to continue */
		if( queryInfoPtr->keySetupAlgo != CRYPT_ALGO_NONE )
			{
			contentListItem->envInfo = CRYPT_ENVINFO_PASSWORD;
			encrInfo->keySetupAlgo = queryInfoPtr->keySetupAlgo;
			encrInfo->keySetupIterations = queryInfoPtr->keySetupIterations;
			memcpy( encrInfo->saltOrIV, queryInfoPtr->salt, 
					queryInfoPtr->saltLength );
			encrInfo->saltOrIVsize = queryInfoPtr->saltLength;
			}
		else
			contentListItem->envInfo = CRYPT_ENVINFO_KEY;
		encrInfo->cryptAlgo = queryInfoPtr->cryptAlgo;
		encrInfo->cryptMode = queryInfoPtr->cryptMode;
		contentListItem->payload = \
						( BYTE * ) contentListItem->object + \
						( ( BYTE * ) queryInfoPtr->dataStart - ( BYTE * ) originalObjectPtr );
		contentListItem->payloadSize = queryInfoPtr->dataLength;
		}
	appendContentListItem( envelopeInfoPtr, contentListItem );

	return( ( int ) queryInfoPtr->size );
	}

/****************************************************************************
*																			*
*						Process Envelope Preamble/Postamble					*
*																			*
****************************************************************************/

/* Process the non-data portions of an envelope.  This is a complex event-
   driven state machine, but instead of reading along a (hypothetical
   Turing-machine) tape, someone has taken the tape and cut it into bits and
   keeps feeding them to us and saying "See what you can do with this" (and
   occasionally "Where's the bloody spoons?").  The following code implements
   this state machine.

	Encr. with key exchange: SET_ENCR -> ENCR -> ENCRCONTENT -> DATA
	Encr. with key agreement: "
	Encr.: ENCRCONTENT -> DATA
	Signed: SET_HASH -> HASH -> CONTENT -> DATA */

static int processPreamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	int length, streamPos = 0, iterationCount = 0, status = CRYPT_OK;

	sMemConnect( &stream, envelopeInfoPtr->buffer, envelopeInfoPtr->bufPos );

	/* If we haven't started doing anything yet, try and read the outer
	   header fields */
	if( state == DEENVSTATE_NONE )
		{
		BYTE algoIDbuffer[ MAX_OID_SIZE ];
		int algoIDlength;

		/* Read the outer CMS header */
		status = readCMSheader( &stream, envelopeOIDinfo, 
								&envelopeInfoPtr->payloadSize, FALSE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}

		/* Determine the next state to continue processing */
		switch( status )
			{
			case ACTION_KEYEXCHANGE:
				envelopeInfoPtr->usage = ACTION_CRYPT;
				if( peekTag( &stream ) != BER_SET )
					{
					/* There may be key agreement data present, try and read 
					   the start of the [0] IMPLICIT SEQUENCE { [0] SET OF 
					   Certificate } */
					readConstructed( &stream, NULL, 0 );
					status = readConstructed( &stream, NULL, 0 );
					if( cryptStatusError( status ) )
						{
						sMemDisconnect( &stream );
						return( status );
						}
					}
				state = DEENVSTATE_SET_ENCR;
				break;

			case ACTION_CRYPT:
				envelopeInfoPtr->usage = ACTION_CRYPT;
				state = DEENVSTATE_ENCRCONTENT;
				break;

			case ACTION_SIGN:
				envelopeInfoPtr->usage = ACTION_SIGN;
				state = DEENVSTATE_SET_HASH;
				break;

			case ACTION_COMPRESS:
				/* With compressed data all we need to do is check that the
				   fixed AlgorithmIdentifier is present and set up the 
				   decompression stream, after which we go straight to the 
				   content */
				envelopeInfoPtr->usage = ACTION_COMPRESS;
				status = readRawObject( &stream, algoIDbuffer, &algoIDlength, 
										MAX_OID_SIZE, BER_SEQUENCE );
				if( !cryptStatusError( status ) && \
					( algoIDlength != sizeofOID( ALGOID_CMS_ZLIB ) || \
					  memcmp( algoIDbuffer, ALGOID_CMS_ZLIB, algoIDlength ) ) )
					status = CRYPT_ERROR_BADDATA;
				else
#ifdef USE_COMPRESSION
					if( inflateInit( &envelopeInfoPtr->zStream ) == Z_OK )
						envelopeInfoPtr->flags |= ENVELOPE_ZSTREAMINITED;
					else
						status = CRYPT_ERROR_MEMORY;
#else
					status = CRYPT_ERROR_NOTAVAIL;
#endif /* USE_COMPRESSION */
				if( cryptStatusError( status ) )
					{
					sMemDisconnect( &stream );
					return( status );
					}
				state = DEENVSTATE_CONTENT;
				break;

			case ACTION_NONE:
				/* Since we go straight to the data payload there's no nested
				   content type, so we explicitly set it to data */
				envelopeInfoPtr->contentType = CRYPT_CONTENT_DATA;
				state = DEENVSTATE_DATA;
				break;

			default:
				assert( NOTREACHED );
			}

		/* Remember how far we got */
		streamPos = stell( &stream );
		}

	/* Keep consuming information until we run out of input or reach the data
	   payload */
	while( state != DEENVSTATE_DONE && iterationCount++ < 256 )
		{
		/* Check that various values are within range.  They can go out of
		   range if the header is corrupted */
		if( envelopeInfoPtr->hdrSetLength < 0 && \
			envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
			{
			status = CRYPT_ERROR_BADDATA;
			break;
			}

		/* Read the start of the cert set from a keyAgreement's [0] IMPLICIT 
		   SEQUENCE { [0] SET OF Certificate } */
		if( state == DEENVSTATE_SET_ENCR )
			{
			/* Read the SET tag and length */
			status = readSetI( &stream, &length );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given we have to look for the EOC after
			   each entry read */
			streamPos = stell( &stream );
			envelopeInfoPtr->hdrSetLength = length;
			state = DEENVSTATE_ENCR;
			}

		/* Read and remember a key exchange object from an EncryptionKeyInfo
		   record */
		if( state == DEENVSTATE_ENCR )
			{
			/* Add the object to the content information list */
			status = addContentListItem( &stream, envelopeInfoPtr, NULL );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state if
			   necessary */
			streamPos = stell( &stream );
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				envelopeInfoPtr->hdrSetLength -= status;
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = DEENVSTATE_ENCRCONTENT;
				}
			else
				{
				status = checkEOC( &stream );
				if( cryptStatusError( status ) )
					break;
				if( status == TRUE )
					state = DEENVSTATE_ENCRCONTENT;
				}
			}

		/* Read the encrypted content information */
		if( state == DEENVSTATE_ENCRCONTENT )
			{
			QUERY_INFO queryInfo;

			/* Read the encrypted content header */
			status = readCMSencrHeader( &stream, nestedContentOIDinfo,
										NULL, &queryInfo );
			if( cryptStatusError( status ) )
				break;
			envelopeInfoPtr->contentType = status;
			envelopeInfoPtr->payloadSize = queryInfo.size;

			/* We've reached encrypted data, we can't go any further until we
			   can either recover the session key from a key exchange object
			   or are fed the session key directly */
			if( envelopeInfoPtr->actionList == NULL )
				{
				/* Since the content can be indefinite-length, we clear the
				   size field to give it a sensible setting */
				queryInfo.size = 0;
				status = addContentListItem( &stream, envelopeInfoPtr, 
											 &queryInfo );
				}
			else
				{
				assert( envelopeInfoPtr->actionList->action == ACTION_CRYPT );

				/* If the session key was recovered from a key exchange 
				   action but we ran out of input data before we could read 
				   the encryptedContent info, it'll be present in the action 
				   list so we use it to set things up for the decryption.  
				   This can only happen if the caller pushes in just enough 
				   data to get past the key exchange actions but not enough 
				   to recover the encryptedContent info and then pushes in a 
				   key exchange action in response to the 
				   CRYPT_ERROR_UNDERFLOW error */
				status = initEnvelopeEncryption( envelopeInfoPtr,
								envelopeInfoPtr->actionList->iCryptHandle, 
								queryInfo.cryptMode, queryInfo.cryptMode, 
								queryInfo.iv, queryInfo.ivLength, 
								FALSE );
				}
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			state = DEENVSTATE_DATA;
			if( envelopeInfoPtr->actionList == NULL )
				{
				/* If we haven't got a session key to decrypt the data that 
				   follows, we can't go beyond this point */
				status = CRYPT_ENVELOPE_RESOURCE;
				break;
				}
			}

		/* Read the start of the SET OF DigestAlgorithmIdentifier */
		if( state == DEENVSTATE_SET_HASH )
			{
			/* Read the SET tag and length */
			status = readSetI( &stream, &length );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given we have to look for the EOC after
			   each entry read */
			streamPos = stell( &stream );
			envelopeInfoPtr->hdrSetLength = length;
			state = DEENVSTATE_HASH;
			}

		/* Read and remember a hash object from a DigestAlgorithmIdentifier
		   record */
		if( state == DEENVSTATE_HASH )
			{
			CRYPT_ALGO_TYPE hashAlgo;
			CRYPT_CONTEXT iHashContext;
			ACTION_LIST *actionListPtr;

			/* Create the hash object from the data */
			status = readContextAlgoID( &stream, &iHashContext, NULL, 
										DEFAULT_TAG );
			if( cryptStatusOK( status ) )
				status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
										  &hashAlgo, CRYPT_CTXINFO_ALGO );
			if( cryptStatusError( status ) )
				break;

			/* Check whether an identical hash action is already present,
			   either through being supplied externally or from a duplicate
			   entry in the set */
			for( actionListPtr = envelopeInfoPtr->actionList; 
				 actionListPtr != NULL; actionListPtr = actionListPtr->next )
				{
				CRYPT_ALGO_TYPE actionHashAlgo;

				status = krnlSendMessage( actionListPtr->iCryptHandle, 
										  IMESSAGE_GETATTRIBUTE,
										  &actionHashAlgo, CRYPT_CTXINFO_ALGO );
				if( cryptStatusOK( status ) && actionHashAlgo == hashAlgo )
					{
					/* There's a duplicate action present, destroy the one
					   we've just created and exit */
					krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
					break;
					}
				}
			if( actionListPtr == NULL )
				{
				/* We didn't find any duplicates, append the new hash action 
				   to the action list and remember that hashing is now 
				   active */
				if( addAction( &envelopeInfoPtr->actionList, 
							   envelopeInfoPtr->memPoolState, ACTION_HASH, 
							   iHashContext ) == NULL )
					{
					status = CRYPT_ERROR_MEMORY;
					break;
					}
				envelopeInfoPtr->dataFlags |= ENVDATA_HASHACTIONSACTIVE;
				}
			assert( envelopeInfoPtr->actionList->action == ACTION_HASH );

			/* Remember where we are and move on to the next state if
			   necessary */
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				envelopeInfoPtr->hdrSetLength -= stell( &stream ) - streamPos;
				streamPos = stell( &stream );
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = DEENVSTATE_CONTENT;
				}
			else
				{
				status = checkEOC( &stream );
				if( cryptStatusError( status ) )
					break;
				if( status == TRUE )
					state = DEENVSTATE_CONTENT;
				}
			}

		/* Read the encapsulated content header */
		if( state == DEENVSTATE_CONTENT )
			{
			status = readCMSheader( &stream, nestedContentOIDinfo, 
									&envelopeInfoPtr->payloadSize, TRUE );
			if( cryptStatusError( status ) )
				break;
			envelopeInfoPtr->contentType = status;
			status = CRYPT_OK;

			/* If there's no content included and it's not an attributes-only
			   message, this is a detached signature with the content supplied 
			   anderswhere */
			if( !envelopeInfoPtr->payloadSize && \
				!( envelopeInfoPtr->flags & ENVELOPE_ATTRONLY ) )
				envelopeInfoPtr->flags |= ENVELOPE_DETACHED_SIG;

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			state = ( envelopeInfoPtr->payloadSize == 0 && \
					  ( envelopeInfoPtr->flags & ( ENVELOPE_DETACHED_SIG | \
												   ENVELOPE_ATTRONLY ) ) ) ? \
					DEENVSTATE_DONE : DEENVSTATE_DATA;
			}

		/* Start the decryption process if necessary */
		if( state == DEENVSTATE_DATA )
			{
			/* Synchronise the data stream processing to the start of the
			   encrypted data and move back to the start of the data 
			   stream */
			status = envelopeInfoPtr->syncDeenvelopeData( envelopeInfoPtr,
														  &stream );
			if( cryptStatusError( status ) )
				break;
			streamPos = 0;

			/* We're done */
			state = DEENVSTATE_DONE;
			assert( actionsOK( envelopeInfoPtr ) );
			}
		}
	if( iterationCount >= 256 )
		return( CRYPT_ERROR_FAILED );
	envelopeInfoPtr->deenvState = state;

	assert( streamPos >= 0 && envelopeInfoPtr->bufPos - streamPos >= 0 );

	/* Consume the input we've processed so far by moving everything past the
	   current position down to the start of the memory buffer */
	length = envelopeInfoPtr->bufPos - streamPos;
	if( length > 0 && streamPos > 0 )
		memmove( envelopeInfoPtr->buffer, envelopeInfoPtr->buffer + streamPos,
				 length );
	envelopeInfoPtr->bufPos = length;

	/* If all went OK but we're still not out of the header information,
	   return an underflow error */
	if( cryptStatusOK( status ) && state != DEENVSTATE_DONE )
		status = CRYPT_ERROR_UNDERFLOW;

	/* Clean up */
	sMemDisconnect( &stream );
	return( status );
	}

static int processPostamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	int length, streamPos = 0, iterationCount = 0, status = CRYPT_OK;

	/* If that's all there is, return */
	if( state == DEENVSTATE_NONE && envelopeInfoPtr->usage != ACTION_SIGN && \
		envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		{
		/* Definite-length data with no trailer, nothing left to process */
		envelopeInfoPtr->deenvState = DEENVSTATE_DONE;
		return( CRYPT_OK );
		}

	/* If there's not enough data left in the stream to do anything with,
	   return immediately.  This isn't strictly necessary but is required to
	   avoid triggering the zero-length stream check */
	if( envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft < 2 )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Start reading the trailer data from the end of the payload */
	sMemConnect( &stream, envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				 envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft );

	/* If we haven't started doing anything yet, figure out what we should be
	   looking for */
	if( state == DEENVSTATE_NONE )
		{
		if( envelopeInfoPtr->usage == ACTION_SIGN )
			{
			DEENV_STATE newState;

			/* Read the SignedData EOC's if necessary */
			if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED )
				{
				if( checkEOC( &stream ) != TRUE || \
					checkEOC( &stream ) != TRUE )
					{
					status = sGetStatus( &stream );
					sMemDisconnect( &stream );
					return( cryptStatusOK( status ) ? \
							CRYPT_ERROR_BADDATA : status );
					}
				}
			else
				{
				/* If the data was encoded using a mixture of definite and
				   indefinite encoding there may be EOC's present even though
				   the length is known, so we skip them if necessary */
				checkEOC( &stream );
				checkEOC( &stream );
				}

			/* Check whether there's a cert chain to follow */
			status = peekTag( &stream );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( &stream );
				return( status );
				}
			newState = ( status == MAKE_CTAG( 0 ) ) ? \
					   DEENVSTATE_CERTSET : DEENVSTATE_SET_SIG;

			/* If we've seen all the signed data, complete the hashing.  When
			   we reach this point there may still be unhashed data left in 
			   the buffer (it won't have been hashed yet because the hashing 
			   is performed when the data is copied out, after unwrapping and 
			   deblocking and whatnot) so we hash it before we wrap up the 
			   hashing */
			if( !( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) )
				{
				if( envelopeInfoPtr->dataLeft > 0 )
					status = 
						envelopeInfoPtr->processExtraData( envelopeInfoPtr,
												envelopeInfoPtr->buffer, 
												envelopeInfoPtr->dataLeft );
				if( !cryptStatusError( status ) )	/* Status == tag */
					status = \
						envelopeInfoPtr->processExtraData( envelopeInfoPtr, 
														   "", 0 );
				if( cryptStatusError( status ) )
					{
					sMemDisconnect( &stream );
					return( status );
					}
				}

			/* Move on to the next state */
			streamPos = stell( &stream );
			state = newState;
			}
		else
			/* Just look for EOC's */
			state = DEENVSTATE_EOC;
		}

	/* Keep consuming information until we run out of input or read the end
	   of the data */
	while( state != DEENVSTATE_DONE && iterationCount++ < 256 )
		{
		/* Check that various values are within range.  They can go out of
		   range if the header is corrupted */
		if( envelopeInfoPtr->hdrSetLength < 0 && \
			envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
			{
			status = CRYPT_ERROR_BADDATA;
			break;
			}

		/* Read the cert chain */
		if( state == DEENVSTATE_CERTSET )
			{
			/* Read the cert chain into the aux.buffer.  We can't import it
			   at this point because we need the SignerInfo to definitively 
			   identify the leaf cert.  Usually there's only one leaf, but
			   there will be more than one if there are multiple signatures
			   present, or if the sending app decides to shovel in assorted
			   (non-relevant) certs */
			length = getStreamObjectLength( &stream );
			if( cryptStatusError( length ) )
				{
				status = length;
				break;
				}
			if( envelopeInfoPtr->auxBuffer == NULL )
				{
				/* Allocate a buffer for the cert chain if necessary.  This
				   may already be allocated if the previous attempt to read
				   the chain failed due to there being insufficient data in
				   the envelope buffer */
				if( ( envelopeInfoPtr->auxBuffer = \
							clAlloc( "processPostamble", length ) ) == NULL )
					{
					status = CRYPT_ERROR_MEMORY;
					break;
					}
				envelopeInfoPtr->auxBufSize = length;
				}
			assert( envelopeInfoPtr->auxBufSize == length );
			status = sread( &stream, envelopeInfoPtr->auxBuffer, 
							envelopeInfoPtr->auxBufSize );
			if( cryptStatusError( status ) )
				break;
			
			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			state = DEENVSTATE_SET_SIG;
			}

		/* Read the start of the SET OF Signature */
		if( state == DEENVSTATE_SET_SIG )
			{
			/* Read the SET tag and length */
			status = readSetI( &stream, &length );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given we have to look for the EOC after
			   each entry read */
			streamPos = stell( &stream );
			envelopeInfoPtr->hdrSetLength = length;
			state = DEENVSTATE_SIG;
			}

		/* Read and remember a signature object from a Signature record */
		if( state == DEENVSTATE_SIG )
			{
			/* Add the object to the content information list */
			status = addContentListItem( &stream, envelopeInfoPtr, NULL );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state if
			   necessary */
			streamPos = stell( &stream );
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				envelopeInfoPtr->hdrSetLength -= status;
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							DEENVSTATE_EOC : DEENVSTATE_DONE;
				}
			else
				{
				status = checkEOC( &stream );
				if( cryptStatusError( status ) )
					break;
				if( status == TRUE )
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							DEENVSTATE_EOC : DEENVSTATE_DONE;
				status = CRYPT_OK;		/* checkEOC() returns a bool.value */
				}
			}

		/* Handle end-of-contents octets.  This gets a bit complicated 
		   because there can be a variable number of EOCs depending on where
		   definite and indefinite encodings were used, so we look for at
		   least one EOC and at most a number that depends on the data type
		   being processed */
		if( state == DEENVSTATE_EOC )
			{
			const int noEOCs = \
					( envelopeInfoPtr->usage == ACTION_SIGN ) ? 3 : \
					( envelopeInfoPtr->usage == ACTION_COMPRESS ) ? 5 : 4;
			int i;

			/* Make sure that there's enough room for the EOCs.  This would
			   be caught anyway as a stream underflow error, but we may as
			   well make the check explicit */
			if( sMemDataLeft( &stream ) < ( noEOCs * 2 ) )
				{
				status = CRYPT_ERROR_UNDERFLOW;
				break;
				}

			/* We need at least one EOC */
			status = checkEOC( &stream );
			if( status == FALSE )
				status = CRYPT_ERROR_BADDATA;
			if( cryptStatusError( status ) )
				break;

			/* Consume any further EOCs up to the maximum amount possible */
			for( i = 1; !cryptStatusError( status ) && i < noEOCs; i++ )
				{
				status = checkEOC( &stream );
				if( status == FALSE )
					status = CRYPT_ERROR_BADDATA;
				}
			if( cryptStatusError( status ) )
				break;
			status = CRYPT_OK;		/* checkEOC() returns a boolean value */

			/* We're done */
			streamPos = stell( &stream );
			state = DEENVSTATE_DONE;
			break;
			}
		}
	if( iterationCount >= 256 )
		return( CRYPT_ERROR_FAILED );
	envelopeInfoPtr->deenvState = state;
	sMemDisconnect( &stream );

	/* Consume the input we've processed so far by moving everything past the
	   current position down to the start of the memory buffer */
	length = envelopeInfoPtr->bufPos - ( envelopeInfoPtr->dataLeft + streamPos );
	if( length > 0 && streamPos > 0 )
		memmove( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				 envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft + streamPos,
				 length );
	envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + length;

	/* Adjust the error state based on what's left in the envelope buffer.
	   If there's data still present, we don't report certain types of errors
	   because they don't affect the data, only the trailer */
	if( envelopeInfoPtr->dataLeft > 0 )
		{
		/* If we've got an underflow error but there's payload data left to
		   be copied out, convert the status to OK since the caller can still
		   continue before they need to copy in more data.  Since there's
		   more data left to process, we return OK_SPECIAL to tell the
		   calling function not to perform any cleanup */
		if( status == CRYPT_ERROR_UNDERFLOW )
			status = OK_SPECIAL;
		}
	else
		/* If all went OK but we're still not out of the header information,
		   return an underflow error */
		if( cryptStatusOK( status ) && state != DEENVSTATE_DONE )
			status = CRYPT_ERROR_UNDERFLOW;

	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

void initCMSDeenveloping( ENVELOPE_INFO *envelopeInfoPtr )
	{
	/* Set the access method pointers */
	envelopeInfoPtr->processPreambleFunction = processPreamble;
	envelopeInfoPtr->processPostambleFunction = processPostamble;

	/* Set up the processing state information */
	envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
	}
#endif /* USE_ENVELOPES */
