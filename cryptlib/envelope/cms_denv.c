/****************************************************************************
*																			*
*					  cryptlib De-enveloping Routines						*
*					 Copyright Peter Gutmann 1996-2006						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "envelope.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "envelope/envelope.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in cms_env.c */

BOOLEAN cmsCheckAlgo( const CRYPT_ALGO_TYPE cryptAlgo,
					  const CRYPT_ALGO_TYPE cryptMode );

#ifdef USE_ENVELOPES

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* OID information used to read enveloped data */

static const CMS_CONTENT_INFO FAR_BSS oidInfoSignedData = { 0, 3 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoEnvelopedData = { 0, 2 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoDigestedData = { 0, 2 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoEncryptedData = { 0, 2 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoCompressedData = { 0, 0 };

static const OID_INFO FAR_BSS envelopeOIDinfo[] = {
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
	{ NULL, 0 }, { NULL, 0 }
	};

static const OID_INFO FAR_BSS nestedContentOIDinfo[] = {
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
	{ NULL, 0 }, { NULL, 0 }
	};

/* Add information about an object to an envelope's content information list */

static int addContentListItem( STREAM *stream, ENVELOPE_INFO *envelopeInfoPtr,
							   QUERY_INFO *externalQueryInfoPtr )
	{
	QUERY_INFO queryInfo, *queryInfoPtr = ( externalQueryInfoPtr == NULL ) ? \
										  &queryInfo : externalQueryInfoPtr;
	CONTENT_LIST *contentListItem;
	BYTE *contentListObjectPtr = NULL;
	int objectSize = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( externalQueryInfoPtr == NULL || \
			isWritePtr( externalQueryInfoPtr, sizeof( QUERY_INFO ) ) );

	/* Find the size of the object, allocate a buffer for it, and copy it
	   across */
	if( externalQueryInfoPtr == NULL )
		{
		/* See what we've got.  This call verifies that all of the object 
		   data is present in the stream, so we don't have to check the
		   following reads */
		status = queryAsn1Object( stream, queryInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		objectSize = ( int ) queryInfoPtr->size;

		/* If it's a valid but unrecognised object type (a new RecipientInfo 
		   type that was added after this version of cryptlib was released), 
		   skip it and continue (if there are no recognised RecipientInfo 
		   types, the code will automatically fall back to asking the user 
		   for a raw session key).  Alternatively, we could just add it to 
		   the content list as an unrecognised object type, but this would 
		   lead to confusion for the caller when non-object-types appear 
		   when they query the current component */
		if( queryInfoPtr->type == CRYPT_OBJECT_NONE )
			{
			sSkip( stream, objectSize );
			return( objectSize );
			}

		/* Read the object data into memory.  The read will always succeed 
		   since it was checked earlier in queryAsn1Object() */
		if( ( contentListObjectPtr = clAlloc( "addContentListItem", \
											  objectSize ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		sread( stream, contentListObjectPtr, objectSize );
		}

	/* Allocate memory for the new content list item and copy information on
	   the item across */
	contentListItem = createContentListItem( envelopeInfoPtr->memPoolState,
							queryInfoPtr->formatType, contentListObjectPtr, 
							objectSize,
							( queryInfoPtr->type == CRYPT_OBJECT_SIGNATURE ) ? \
								TRUE : FALSE );
	if( contentListItem == NULL )
		{
		if( externalQueryInfoPtr == NULL )
			clFree( "addContentListItem", contentListObjectPtr );
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
		if( queryInfoPtr->ivLength > 0 )
			{
			if( queryInfoPtr->ivLength > CRYPT_MAX_IVSIZE )
				{
				/* Restricted in query code to CRYPT_MAX_IVSIZE */
				assert( NOTREACHED );
				return( CRYPT_ERROR_BADDATA );
				}
			memcpy( encrInfo->saltOrIV, queryInfoPtr->iv, 
					queryInfoPtr->ivLength );
			encrInfo->saltOrIVsize = queryInfoPtr->ivLength;
			}
		}
	if( queryInfoPtr->type == CRYPT_OBJECT_PKCENCRYPTED_KEY || \
		queryInfoPtr->type == CRYPT_OBJECT_SIGNATURE )
		{
		/* Remember details of the enveloping info that we require to 
		   continue */
		if( queryInfoPtr->type == CRYPT_OBJECT_PKCENCRYPTED_KEY )
			contentListItem->envInfo = CRYPT_ENVINFO_PRIVATEKEY;
		else
			{
			contentListItem->envInfo = CRYPT_ENVINFO_SIGNATURE;
			contentListItem->clSigInfo.hashAlgo = queryInfoPtr->hashAlgo;
			}
		if( queryInfoPtr->formatType == CRYPT_FORMAT_CMS )
			{
			contentListItem->issuerAndSerialNumber = contentListObjectPtr + \
													 queryInfoPtr->iAndSStart;
			contentListItem->issuerAndSerialNumberSize = queryInfoPtr->iAndSLength;
			}
		else
			{
			if( queryInfoPtr->keyIDlength > CRYPT_MAX_HASHSIZE )
				{
				/* Restricted in query code to CRYPT_MAX_HASHSIZE */
				assert( NOTREACHED );
				return( CRYPT_ERROR_BADDATA );
				}
			memcpy( contentListItem->keyID, queryInfoPtr->keyID,
					queryInfoPtr->keyIDlength );
			contentListItem->keyIDsize = queryInfoPtr->keyIDlength;
			}
		contentListItem->payload = contentListObjectPtr + \
								   queryInfoPtr->dataStart;
		contentListItem->payloadSize = queryInfoPtr->dataLength;
		if( queryInfoPtr->type == CRYPT_OBJECT_SIGNATURE && \
			queryInfoPtr->formatType == CRYPT_FORMAT_CMS && \
			queryInfoPtr->unauthAttributeStart > 0 )
			{
			CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;

			sigInfo->extraData2 = contentListObjectPtr + \
								  queryInfoPtr->unauthAttributeStart;
			sigInfo->extraData2Length = queryInfoPtr->unauthAttributeLength;
			}
		}
	if( queryInfoPtr->type == CRYPT_OBJECT_ENCRYPTED_KEY )
		{
		CONTENT_ENCR_INFO *encrInfo = &contentListItem->clEncrInfo;

		/* Remember details of the enveloping info that we require to 
		   continue */
		if( queryInfoPtr->keySetupAlgo != CRYPT_ALGO_NONE )
			{
			contentListItem->envInfo = CRYPT_ENVINFO_PASSWORD;
			encrInfo->keySetupAlgo = queryInfoPtr->keySetupAlgo;
			encrInfo->keySetupIterations = queryInfoPtr->keySetupIterations;
			if( queryInfoPtr->saltLength > 0 )
				{
				if( queryInfoPtr->saltLength > CRYPT_MAX_HASHSIZE )
					{
					/* Restricted in query code to CRYPT_MAX_HASHSIZE */
					assert( NOTREACHED );
					return( CRYPT_ERROR_BADDATA );
					}
				memcpy( encrInfo->saltOrIV, queryInfoPtr->salt,
						queryInfoPtr->saltLength );
				encrInfo->saltOrIVsize = queryInfoPtr->saltLength;
				}
			}
		else
			contentListItem->envInfo = CRYPT_ENVINFO_KEY;
		encrInfo->cryptAlgo = queryInfoPtr->cryptAlgo;
		encrInfo->cryptMode = queryInfoPtr->cryptMode;
		contentListItem->payload = contentListObjectPtr + \
								   queryInfoPtr->dataStart;
		contentListItem->payloadSize = queryInfoPtr->dataLength;
		}
	appendContentListItem( envelopeInfoPtr, contentListItem );

	return( ( int ) queryInfoPtr->size );
	}

/****************************************************************************
*																			*
*							Header Processing Routines						*
*																			*
****************************************************************************/

/* Process the outer CMS envelope header */

static int processEnvelopeHeader( ENVELOPE_INFO *envelopeInfoPtr, 
								  STREAM *stream, DEENV_STATE *state )
	{
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( state, sizeof( DEENV_STATE ) ) );

	/* Read the outer CMS header */
	status = readCMSheader( stream, envelopeOIDinfo,
							&envelopeInfoPtr->payloadSize, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Determine the next state to continue processing */
	switch( status )
		{
		case ACTION_KEYEXCHANGE:
#ifdef USE_KEA
			status = peekTag( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( status != BER_SET )
				{
				/* There may be key agreement data present, try and read the 
				   start of the [0] IMPLICIT SEQUENCE { [0] SET OF Certificate } */
				readConstructed( stream, NULL, 0 );
				status = readConstructed( stream, NULL, 0 );
				if( cryptStatusError( status ) )
					return( status );
				}
#endif /* USE_KEA */
			envelopeInfoPtr->usage = ACTION_CRYPT;
			*state = DEENVSTATE_SET_ENCR;
			break;

		case ACTION_CRYPT:
			envelopeInfoPtr->usage = ACTION_CRYPT;
			*state = DEENVSTATE_ENCRCONTENT;
			break;

		case ACTION_SIGN:
			envelopeInfoPtr->usage = ACTION_SIGN;
			*state = DEENVSTATE_SET_HASH;
			break;

		case ACTION_COMPRESS:
			/* With compressed data all that we need to do is check that the 
			   fixed AlgorithmIdentifier is present and set up the 
			   decompression stream, after which we go straight to the 
			   content */
			status = readGenericAlgoID( stream, OID_ZLIB ); 
			if( cryptStatusError( status ) )
				return( status );
			envelopeInfoPtr->usage = ACTION_COMPRESS;
#ifdef USE_COMPRESSION
			if( inflateInit( &envelopeInfoPtr->zStream ) != Z_OK )
				return( CRYPT_ERROR_MEMORY );
			envelopeInfoPtr->flags |= ENVELOPE_ZSTREAMINITED;
			*state = DEENVSTATE_CONTENT;
#else
			return( CRYPT_ERROR_NOTAVAIL );
#endif /* USE_COMPRESSION */
			break;

		case ACTION_NONE:
			/* Since we go straight to the data payload there's no nested 
			   content type, so we explicitly set it to "data" */
			envelopeInfoPtr->contentType = CRYPT_CONTENT_DATA;
			*state = DEENVSTATE_DATA;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
		}

	return( CRYPT_OK );
	}

/* Process the encrypted content header */

static int processEncryptionHeader( ENVELOPE_INFO *envelopeInfoPtr, 
									STREAM *stream )
	{
	QUERY_INFO queryInfo;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the encrypted content header */
	status = readCMSencrHeader( stream, nestedContentOIDinfo, NULL, 
								&queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	envelopeInfoPtr->contentType = status;
	envelopeInfoPtr->payloadSize = queryInfo.size;

	/* We've reached encrypted data, we can't go any further until we can 
	   either recover the session key from a key exchange object or are fed 
	   the session key directly */
	if( envelopeInfoPtr->actionList == NULL )
		{
		/* Since the content can be indefinite-length, we clear the size 
		   field to give it a sensible setting */
		queryInfo.size = 0;
		return( addContentListItem( stream, envelopeInfoPtr, &queryInfo ) );
		}

	assert( envelopeInfoPtr->actionList != NULL && \
			envelopeInfoPtr->actionList->action == ACTION_CRYPT );

	/* If the session key was recovered from a key exchange action but we 
	   ran out of input data before we could read the encryptedContent info, 
	   it'll be present in the action list so we use it to set things up for 
	   the decryption.  This can only happen if the caller pushes in just 
	   enough data to get past the key exchange actions but not enough to 
	   recover the encryptedContent info and then pushes in a key exchange 
	   action in response to the CRYPT_ERROR_UNDERFLOW error */
	return( initEnvelopeEncryption( envelopeInfoPtr,
							envelopeInfoPtr->actionList->iCryptHandle,
							queryInfo.cryptMode, queryInfo.cryptMode,
							queryInfo.iv, queryInfo.ivLength,
							FALSE ) );
	}

/* Process the hash object header */

static int processHashHeader( ENVELOPE_INFO *envelopeInfoPtr, STREAM *stream )
	{
	CRYPT_ALGO_TYPE hashAlgo;
	CRYPT_CONTEXT iHashContext;
	ACTION_LIST *actionListPtr;
	int iterationCount = 0, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Create the hash object from the data */
	status = readContextAlgoID( stream, &iHashContext, NULL, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
								  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );

	/* Check whether an identical hash action is already present, either 
	   through being supplied externally or from a duplicate entry in the 
	   set */
	for( actionListPtr = envelopeInfoPtr->actionList;
		 actionListPtr != NULL && iterationCount++ < FAILSAFE_ITERATIONS_MAX; 
		 actionListPtr = actionListPtr->next )
		{
		CRYPT_ALGO_TYPE actionHashAlgo;

		status = krnlSendMessage( actionListPtr->iCryptHandle,
								  IMESSAGE_GETATTRIBUTE, &actionHashAlgo, 
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) && actionHashAlgo == hashAlgo )
			{
			/* There's a duplicate action present, destroy the one that 
			   we've just created and continue */
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( CRYPT_OK );
			}
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MAX )
		retIntError();

	/* We didn't find any duplicates, append the new hash action to the 
	   action list and remember that hashing is now active */
	if( addAction( &envelopeInfoPtr->actionList, 
				   envelopeInfoPtr->memPoolState, ACTION_HASH, 
				   iHashContext ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	envelopeInfoPtr->dataFlags |= ENVDATA_HASHACTIONSACTIVE;
	assert( envelopeInfoPtr->actionList != NULL && \
			envelopeInfoPtr->actionList->action == ACTION_HASH );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Trailer Processing Routines						*
*																			*
****************************************************************************/

/* Process the signed data trailer */

static int processSignedTrailer( ENVELOPE_INFO *envelopeInfoPtr, 
								 STREAM *stream, DEENV_STATE *state )
	{
	DEENV_STATE newState;
	int tag, status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( state, sizeof( DEENV_STATE ) ) );

	/* Read the SignedData EOC's if necessary */
	if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED )
		{
		if( ( status = checkEOC( stream ) ) != TRUE || \
			( status = checkEOC( stream ) ) != TRUE )
			return( cryptStatusOK( status ) ? \
					CRYPT_ERROR_BADDATA : status );
		}
	else
		{
		/* If the data was encoded using a mixture of definite and 
		   indefinite encoding there may be EOC's present even though the 
		   length is known, so we skip them if necessary.  If there's a 
		   problem, checkEOC() will set the stream error state and we'll 
		   catch it at the peekTag() that follows */
		if( checkEOC( stream ) == TRUE )
			checkEOC( stream );
		}

	/* Check whether there's a cert chain to follow */
	tag = peekTag( stream );
	if( cryptStatusError( tag ) )
		return( tag );
	newState = ( tag == MAKE_CTAG( 0 ) ) ? \
			   DEENVSTATE_CERTSET : DEENVSTATE_SET_SIG;

	/* If we've seen all of the signed data, complete the hashing.  When we 
	   reach this point there may still be unhashed data left in the buffer 
	   (it won't have been hashed yet because the hashing is performed when 
	   the data is copied out, after unwrapping and deblocking and whatnot) 
	   so we hash it before we wrap up the hashing */
	if( !( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) )
		{
		if( envelopeInfoPtr->dataLeft > 0 )
			status = envelopeInfoPtr->processExtraData( envelopeInfoPtr,
												envelopeInfoPtr->buffer,
												envelopeInfoPtr->dataLeft );
		if( cryptStatusOK( status ) )
			status = envelopeInfoPtr->processExtraData( envelopeInfoPtr,
														"", 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Move on to the next state */
	*state = newState;

	return( CRYPT_OK );
	}

/* Process any remaining EOCs.  This gets a bit complicated because there 
   can be a variable number of EOCs depending on where definite and 
   indefinite encodings were used, so we look for at least one EOC and at 
   most a number that depends on the data type being processed */

static int processEOCTrailer( ENVELOPE_INFO *envelopeInfoPtr, STREAM *stream )
	{
	const int noEOCs = ( envelopeInfoPtr->usage == ACTION_NONE ) ? 2 : \
					   ( envelopeInfoPtr->usage == ACTION_SIGN ) ? 3 : \
					   ( envelopeInfoPtr->usage == ACTION_COMPRESS ) ? 5 : 4;
	int i;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Consume any EOCs up to the maximum amount possible */
	for( i = 0; i < noEOCs; i++ )
		{
		const int value = checkEOC( stream );
		if( cryptStatusError( value ) )
			{
			/* If we got at least one EOC before we ran out of input, we let
			   it go at that - there's not much point in forcing the user to
			   push in a few extra zero bytes that aren't used for anything
			   anyway */
			if( value == CRYPT_ERROR_UNDERFLOW && i > 0 )
				return( CRYPT_OK );

			return( value );
			}
		if( value == FALSE )
			return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
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
	Encr. with key agreement:	"		   "		  "			  "
	Encr.: ENCRCONTENT -> DATA
	Signed: SET_HASH -> HASH -> CONTENT -> DATA */

static int processPreamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	int length, streamPos = 0, iterationCount = 0, status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envelopeInfoPtr->deenvState >= DEENVSTATE_NONE && \
			envelopeInfoPtr->deenvState <= DEENVSTATE_DONE );

	sMemConnect( &stream, envelopeInfoPtr->buffer, envelopeInfoPtr->bufPos );

	/* If we haven't started doing anything yet, try and read the outer
	   header fields */
	if( state == DEENVSTATE_NONE )
		{
		status = processEnvelopeHeader( envelopeInfoPtr, &stream, &state );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}

		/* Remember how far we got */
		streamPos = stell( &stream );
		}

	/* Keep consuming information until we either run out of input or reach 
	   the data payload.  Although in theory we should really use 
	   FAILSAFE_ITERATIONS_MED for this loop, in practice we have to use
	   FAILSAFE_ITERATIONS_LARGE because it's possible to generate S/MIME 
	   messages with large numbers of recipients for mailing lists.  This 
	   would never occur in any normal usage, but we have to allow for it for
	   mailing-list use */
	while( state != DEENVSTATE_DONE && \
		   iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
		{
		/* Read the start of the SET OF RecipientInfo/SET OF 
		   DigestAlgorithmIdentifier */
		if( state == DEENVSTATE_SET_ENCR || state == DEENVSTATE_SET_HASH )
			{
			long setLength;

			/* Read the SET tag and length.  We have to read the length as
			   a long value in order to handle cases where there's large key 
			   management info data and a great many recipients */
			status = ( state == DEENVSTATE_SET_ENCR ) ? \
					 readLongSet( &stream, &setLength ) : \
					 readSetI( &stream, &length );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given (setLength == CRYPT_UNUSED) we 
			   have to look for the EOC after each entry read */
			streamPos = stell( &stream );
			if( state == DEENVSTATE_SET_ENCR ) 
				{
				envelopeInfoPtr->hdrSetLength = setLength;
				state = DEENVSTATE_ENCR;
				}
			else
				{
				envelopeInfoPtr->hdrSetLength = length;
				state = DEENVSTATE_HASH;
				}
			}

		/* Read and remember a key exchange object from an EncryptionKeyInfo
		   record */
		if( state == DEENVSTATE_ENCR )
			{
			/* Add the object to the content information list */
			length = addContentListItem( &stream, envelopeInfoPtr, NULL );
			if( cryptStatusError( length ) )
				{
				status = length;
				break;
				}

			/* Remember where we are and move on to the next state if
			   necessary */
			streamPos = stell( &stream );
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				if( length > envelopeInfoPtr->hdrSetLength )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				envelopeInfoPtr->hdrSetLength -= length;
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = DEENVSTATE_ENCRCONTENT;
				}
			else
				{
				const int value = checkEOC( &stream );
				if( cryptStatusError( value ) )
					{
					status = value;
					break;
					}
				if( value == TRUE )
					state = DEENVSTATE_ENCRCONTENT;
				}
			}

		/* Read the encrypted content information */
		if( state == DEENVSTATE_ENCRCONTENT )
			{
			status = processEncryptionHeader( envelopeInfoPtr, &stream );
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

		/* Read and remember a hash object from a DigestAlgorithmIdentifier
		   record */
		if( state == DEENVSTATE_HASH )
			{
			status = processHashHeader( envelopeInfoPtr, &stream );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state if
			   necessary */
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				length = stell( &stream ) - streamPos;
				if( length < 0 || length > envelopeInfoPtr->hdrSetLength )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				envelopeInfoPtr->hdrSetLength -= length;
				streamPos = stell( &stream );
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = DEENVSTATE_CONTENT;
				}
			else
				{
				const int value = checkEOC( &stream );
				if( cryptStatusError( value ) )
					{
					status = value;
					break;
					}
				if( value == TRUE )
					state = DEENVSTATE_CONTENT;
				}
			}

		/* Read the encapsulated content header */
		if( state == DEENVSTATE_CONTENT )
			{
			length = readCMSheader( &stream, nestedContentOIDinfo,
									&envelopeInfoPtr->payloadSize, TRUE );
			if( cryptStatusError( length ) )
				{
				status = length;
				break;
				}
			envelopeInfoPtr->contentType = length;

			/* If there's no content included and it's not an attributes-only
			   message, this is a detached signature with the content supplied
			   anderswhere */
			if( envelopeInfoPtr->payloadSize == 0 && \
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
			streamPos = 0;	/* Data has been resync'd with start of stream */

			/* We're done */
			state = DEENVSTATE_DONE;
			if( !checkActions( envelopeInfoPtr ) )
				{
				/* Sanity check */
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			}
		}
	sMemDisconnect( &stream );
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		/* Technically this would be an overflow, but that's a recoverable
		   error so we make it a BADDATA, which is really what it is */
		return( CRYPT_ERROR_BADDATA );
	envelopeInfoPtr->deenvState = state;

	assert( streamPos >= 0 && envelopeInfoPtr->bufPos - streamPos >= 0 );

	/* Consume the input that we've processed so far by moving everything 
	   past the current position down to the start of the memory buffer */
	length = envelopeInfoPtr->bufPos - streamPos;
	assert( length >= 0 );
	if( length > 0 && streamPos > 0 )
		memmove( envelopeInfoPtr->buffer, envelopeInfoPtr->buffer + streamPos,
				 length );
	envelopeInfoPtr->bufPos = length;
	if( cryptStatusError( status ) )
		return( status );

	/* If all went OK but we're still not out of the header information,
	   return an underflow error */
	return( ( state != DEENVSTATE_DONE ) ? CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
	}

static int processPostamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	int length, streamPos = 0, iterationCount = 0, status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envelopeInfoPtr->deenvState >= DEENVSTATE_NONE && \
			envelopeInfoPtr->deenvState <= DEENVSTATE_DONE );

	/* If that's all there is, return */
	if( state == DEENVSTATE_NONE && \
		envelopeInfoPtr->usage != ACTION_SIGN && \
		envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		{
		/* Definite-length data with no trailer, nothing left to process */
		envelopeInfoPtr->deenvState = DEENVSTATE_DONE;
		return( CRYPT_OK );
		}

	/* If there's not enough data left in the stream to do anything with, 
	   don't try and go any further */
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
			status = processSignedTrailer( envelopeInfoPtr, &stream, 
										   &state );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( &stream );
				return( status );
				}
			}
		else
			/* Just look for EOC's */
			state = DEENVSTATE_EOC;

		streamPos = stell( &stream );
		}

	/* Keep consuming information until we run out of input or reach the end
	   of the data */
	while( state != DEENVSTATE_DONE && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED )
		{
		/* Read the cert chain */
		if( state == DEENVSTATE_CERTSET )
			{
			/* Read the cert chain into the aux.buffer.  We can't import it
			   yet at this point because we need the SignerInfo to 
			   definitively identify the leaf cert.  Usually there's only 
			   one leaf, but there will be more than one if there are 
			   multiple signatures present, or if the sending app decides to 
			   shovel in assorted (non-relevant) certs */
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
			length = addContentListItem( &stream, envelopeInfoPtr, NULL );
			if( cryptStatusError( length ) )
				{
				status = length;
				break;
				}

			/* Remember where we are and move on to the next state if
			   necessary */
			streamPos = stell( &stream );
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				if( length < 0 || length > envelopeInfoPtr->hdrSetLength )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				envelopeInfoPtr->hdrSetLength -= length;
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							DEENVSTATE_EOC : DEENVSTATE_DONE;
				}
			else
				{
				const int value = checkEOC( &stream );
				if( cryptStatusError( value ) )
					{
					status = value;
					break;
					}
				if( value == TRUE )
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							DEENVSTATE_EOC : DEENVSTATE_DONE;
				}
			}

		/* Handle end-of-contents octets */
		if( state == DEENVSTATE_EOC )
			{
			status = processEOCTrailer( envelopeInfoPtr, &stream );
			if( cryptStatusError( status ) )
				break;

			/* We're done */
			streamPos = stell( &stream );
			state = DEENVSTATE_DONE;
			break;
			}
		}
	sMemDisconnect( &stream );
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		/* Technically this would be an overflow, but that's a recoverable
		   error so we make it a BADDATA, which is really what it is */
		return( CRYPT_ERROR_BADDATA );
	envelopeInfoPtr->deenvState = state;

	/* Consume the input that we've processed so far by moving everything 
	   past the current position down to the start of the memory buffer */
	length = envelopeInfoPtr->bufPos - ( envelopeInfoPtr->dataLeft + streamPos );
	assert( length >= 0 );
	if( length > 0 && streamPos > 0 )
		memmove( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				 envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft + streamPos,
				 length );
	envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + length;
	if( cryptStatusError( status ) )
		{
		/* If we got an underflow error but there's payload data left to be 
		   copied out, convert the status to OK since the caller can still
		   continue before they need to copy in more data.  Since there's
		   more data left to process, we return OK_SPECIAL to tell the
		   calling function not to perform any cleanup */
		if( status == CRYPT_ERROR_UNDERFLOW && envelopeInfoPtr->dataLeft > 0 )
			return( OK_SPECIAL );

		return( status );
		}

	/* If all went OK but we're still not out of the header information, 
	   return an underflow error */
	return( ( state != DEENVSTATE_DONE ) ? CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

void initCMSDeenveloping( ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE );

	/* Set the access method pointers */
	envelopeInfoPtr->processPreambleFunction = processPreamble;
	envelopeInfoPtr->processPostambleFunction = processPostamble;
	envelopeInfoPtr->checkAlgo = cmsCheckAlgo;

	/* Set up the processing state information */
	envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
	}
#endif /* USE_ENVELOPES */
