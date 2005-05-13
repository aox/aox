/****************************************************************************
*																			*
*					 cryptlib PGP Enveloping Routines						*
*					 Copyright Peter Gutmann 1996-2004						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "envelope.h"
  #include "pgp.h"
  #include "misc_rw.h"
#elif defined( INC_CHILD )
  #include "envelope.h"
  #include "pgp.h"
  #include "../misc/misc_rw.h"
#else
  #include "envelope/envelope.h"
  #include "envelope/pgp.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

#ifdef USE_PGP

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Check that a requested algorithm type is valid with PGP data */

static int checkCryptAlgo( const CRYPT_ALGO_TYPE cryptAlgo, 
						   const CRYPT_ALGO_TYPE cryptMode )
	{
	return( ( cryptlibToPgpAlgo( cryptAlgo ) != PGP_ALGO_NONE && \
			  cryptMode == CRYPT_MODE_CFB ) ? \
			CRYPT_OK : CRYPT_ERROR_NOTAVAIL );
	}

static int checkHashAlgo( const CRYPT_ALGO_TYPE hashAlgo )
	{
	return( ( cryptlibToPgpAlgo( hashAlgo ) != PGP_ALGO_NONE ) ? \
			CRYPT_OK : CRYPT_ERROR_NOTAVAIL );
	}

/****************************************************************************
*																			*
*						Write Key Exchange/Signature Packets				*
*																			*
****************************************************************************/

/* One-pass signature info:

	byte	version = 3
	byte	sigType
	byte	hashAlgo
	byte	sigAlgo
	byte[8]	keyID
	byte	1 

   This is additional header data written at the start of a block of signed
   data, so we can't write it as part of the standard PGP packet read/write
   routines */

static int writeSignatureInfoPacket( STREAM *stream, 
									 const CRYPT_CONTEXT iSignContext,
									 const CRYPT_CONTEXT iHashContext )
	{
	CRYPT_ALGO_TYPE hashAlgo, signAlgo;
	BYTE keyID[ PGP_KEYID_SIZE ];
	int status;

	/* Get the signature information */
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE, 
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE, 
								  &signAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, keyID, PGP_KEYID_SIZE );
		status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the signature info packet */
	pgpWritePacketHeader( stream, PGP_PACKET_SIGNATURE_ONEPASS, \
						  1 + 1 + 1 + 1 + PGP_KEYID_SIZE + 1 );
	sputc( stream, 3 );		/* Version = 3 (OpenPGP) */
	sputc( stream, 0 );		/* Binary document sig. */
	sputc( stream, cryptlibToPgpAlgo( hashAlgo ) );
	sputc( stream, cryptlibToPgpAlgo( signAlgo ) );
	swrite( stream, keyID, PGP_KEYID_SIZE );
	return( sputc( stream, 1 ) );
	}

/****************************************************************************
*																			*
*					Envelope Pre/Post-processing Functions					*
*																			*
****************************************************************************/

/* The following functions take care of pre/post-processing of envelope data
   during the enveloping process */

static int preEnvelopeEncrypt( ENVELOPE_INFO *envelopeInfoPtr )
	{
	CRYPT_DEVICE iCryptDevice = CRYPT_ERROR;
	ACTION_LIST *actionListPtr;
	int status;

	/* Create the session key if necessary */
	if( envelopeInfoPtr->actionList == NULL )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;
		static const CRYPT_MODE_TYPE mode = CRYPT_MODE_CFB;

		/* Create a default encryption action and add it to the action
		   list */
		setMessageCreateObjectInfo( &createInfo, 
									envelopeInfoPtr->defaultAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		if( envelopeInfoPtr->defaultAlgo == CRYPT_ALGO_BLOWFISH )
			{
			static const int keySize = 16;

			/* If we're using an algorithm with a variable-length key, 
			   restrict it to a fixed length.  There shouldn't be any need
			   for this because the key length is communicated as part of 
			   the wrapped key, but some implementations choke if it's not 
			   exactly 128 bits */
			krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
							 ( void * ) &keySize, CRYPT_CTXINFO_KEYSIZE );
			}
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
						 ( void * ) &mode, CRYPT_CTXINFO_MODE );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_CTX_GENKEY, NULL, FALSE );
		if( cryptStatusOK( status ) && \
			addAction( &envelopeInfoPtr->actionList, 
					   envelopeInfoPtr->memPoolState, ACTION_CRYPT, 
					   createInfo.cryptHandle ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, 
							  IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}
	else
		{
		/* If the session key context is tied to a device, get its handle so 
		   we can check that all key exchange objects are also in the same 
		   device */
		status = krnlSendMessage( envelopeInfoPtr->actionList->iCryptHandle, 
								  MESSAGE_GETDEPENDENT, &iCryptDevice, 
								  OBJECT_TYPE_DEVICE );
		if( cryptStatusError( status ) )
			iCryptDevice = CRYPT_ERROR;
		}

	/* Notify the kernel that the session key context is attached to the 
	   envelope.  This is an internal object used only by the envelope so we
	   tell the kernel not to increment its reference count when it attaches
	   it */
	krnlSendMessage( envelopeInfoPtr->objectHandle, IMESSAGE_SETDEPENDENT, 
					 &envelopeInfoPtr->actionList->iCryptHandle, 
					 SETDEP_OPTION_NOINCREF );

	/* Now walk down the list of key exchange actions connecting each one to 
	   the session key action */
	for( actionListPtr = findAction( envelopeInfoPtr->preActionList,
									 ACTION_KEYEXCHANGE_PKC );
		 actionListPtr != NULL && \
			actionListPtr->action == ACTION_KEYEXCHANGE_PKC;
		 actionListPtr = actionListPtr->next )
		{
		/* If the session key context is tied to a device, make sure that 
		   the key exchange object is in the same device */
		if( iCryptDevice != CRYPT_ERROR )
			{
			CRYPT_DEVICE iKeyexDevice;

			status = krnlSendMessage( actionListPtr->iCryptHandle, 
									  MESSAGE_GETDEPENDENT, &iKeyexDevice, 
									  OBJECT_TYPE_DEVICE );
			if( cryptStatusError( status ) || iCryptDevice != iKeyexDevice )
				return( CRYPT_ERROR_INVALID );
			}

		/* Remember that we now have a controlling action and connect the
		   controller to the subject */
		envelopeInfoPtr->actionList->flags &= ~ACTION_NEEDSCONTROLLER;
		actionListPtr->associatedAction = envelopeInfoPtr->actionList;

		/* Evaluate the size of the exported action.  We only get PKC 
		   actions at this point so we don't have to provide any special-
		   case handling for other key exchange types */
		status = iCryptExportKeyEx( NULL, &actionListPtr->encodedSize, 0,
								CRYPT_FORMAT_PGP, 
								envelopeInfoPtr->actionList->iCryptHandle,
								actionListPtr->iCryptHandle, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}
	return( CRYPT_OK );
	}

static int preEnvelopeSign( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr = envelopeInfoPtr->postActionList;

	/* Evaluate the size of the signature action */
	return( iCryptCreateSignatureEx( NULL, &actionListPtr->encodedSize, 0, 
							CRYPT_FORMAT_PGP, actionListPtr->iCryptHandle, 
							envelopeInfoPtr->actionList->iCryptHandle,
							CRYPT_UNUSED, CRYPT_UNUSED ) );
	}

/****************************************************************************
*																			*
*							Emit Envelope Preamble/Postamble				*
*																			*
****************************************************************************/

/* Output as much of the preamble as possible into the envelope buffer */

static int emitPreamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	int status = CRYPT_OK;

	/* If we've finished processing the header information, don't do
	   anything */
	if( envelopeInfoPtr->envState == ENVSTATE_DONE )
		return( CRYPT_OK );

	/* If we haven't started doing anything yet, perform various final
	   initialisations */
	if( envelopeInfoPtr->envState == ENVSTATE_NONE )
		{
		/* If there's no nested content type set, default to plain data */
		if( envelopeInfoPtr->contentType == CRYPT_CONTENT_NONE )
			envelopeInfoPtr->contentType = CRYPT_CONTENT_DATA;

		/* If there's an absolute data length set, remember it for when we 
		   copy in data */
		if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
			envelopeInfoPtr->segmentSize = envelopeInfoPtr->payloadSize;

		/* Perform any remaining initialisation.  Since PGP derives the 
		   session key directly from the user password, we only perform this
		   initialisation if there are PKC key exchange actions present */
		if( envelopeInfoPtr->usage == ACTION_CRYPT && \
			findAction( envelopeInfoPtr->preActionList,
						ACTION_KEYEXCHANGE_PKC ) != NULL )
			status = preEnvelopeEncrypt( envelopeInfoPtr );
		else
			if( envelopeInfoPtr->usage == ACTION_SIGN )
				status = preEnvelopeSign( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			return( status );

		/* Delete any orphaned actions such as automatically-added hash 
		   actions that were overridden with user-supplied alternate 
		   actions */
		deleteUnusedActions( envelopeInfoPtr );

		/* We're ready to go, prepare to emit the outer header */
		envelopeInfoPtr->envState = ENVSTATE_HEADER;
		assert( actionsOK( envelopeInfoPtr ) );
		}

	/* Emit the outer header.  This always follows directly from the final
	   initialisation step, but we keep the two logically distinct to 
	   emphasise that the former is merely finalised enveloping actions
	   without performing any header processing, while the latter is that
	   first stage that actually emits header data */
	if( envelopeInfoPtr->envState == ENVSTATE_HEADER )
		{
		/* If we're encrypting, set up the encryption-related information.
		   Since PGP doesn't perform a key exchange of a session key when 
		   conventionally-encrypting data, the encryption information could 
		   be coming from either an encryption action (derived from a 
		   password) or a conventional key exchange action that results in 
		   the direct creation of a session encryption key */
		if( envelopeInfoPtr->usage == ACTION_CRYPT )
			{
			status = initEnvelopeEncryption( envelopeInfoPtr,
								envelopeInfoPtr->actionList->iCryptHandle, 
								CRYPT_ALGO_NONE, CRYPT_MODE_NONE, NULL, 0, 
								FALSE );
			if( cryptStatusError( status ) )
				return( status );

			/* Prepare to start emitting the key exchange (PKC-encrypted) or 
			   session key (conventionally encrypted) actions */
			envelopeInfoPtr->lastAction = \
								findAction( envelopeInfoPtr->preActionList,
											ACTION_KEYEXCHANGE_PKC );
			if( envelopeInfoPtr->lastAction == NULL )
				/* There's no key exchange action, we're using a raw session
				   key derived from a password */
				envelopeInfoPtr->lastAction = envelopeInfoPtr->actionList;
			envelopeInfoPtr->envState = ENVSTATE_KEYINFO;
			}
		else
			{
			STREAM stream;
			int length;

			/* If we're not encrypting data (i.e. there's only a single 
			   packet present rather than a packet preceded by a pile of key
			   exchange actions), write the appropriate PGP header based on 
			   the envelope usage */
			sMemOpen( &stream, envelopeInfoPtr->buffer, 
					  envelopeInfoPtr->bufSize );
			switch( envelopeInfoPtr->usage )
				{
				case ACTION_SIGN:
					if( !( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) )
						{
						status = writeSignatureInfoPacket( &stream, 
								envelopeInfoPtr->postActionList->iCryptHandle,
								envelopeInfoPtr->actionList->iCryptHandle );
						if( cryptStatusError( status ) )
							break;
						}

					/* Since we can only sign literal data, we need to 
					   explicitly write an inner data header */
					assert( envelopeInfoPtr->contentType == CRYPT_CONTENT_DATA );
					envelopeInfoPtr->envState = ENVSTATE_DATA;
					break;

				case ACTION_NONE:
					/* Write the header followed by an indicator that we're 
					   using opaque content, a zero-length filename, and no 
					   date */
					pgpWritePacketHeader( &stream, PGP_PACKET_DATA, 
						envelopeInfoPtr->payloadSize + PGP_DATA_HEADER_SIZE );
					swrite( &stream, PGP_DATA_HEADER, PGP_DATA_HEADER_SIZE );
					break;

				case ACTION_COMPRESS:
					/* Compressed data packets use a special unkown-length 
					   encoding that doesn't work like any other PGP packet 
					   type, so we can't use pgpWritePacketHeader() for this
					   packet type but have to hand-assemble the header
					   ourselves */
					sputc( &stream, PGP_CTB_COMPRESSED );
					sputc( &stream, PGP_ALGO_ZLIB );
					if( envelopeInfoPtr->contentType == CRYPT_CONTENT_DATA )
						/* If there's no inner content type, we need to 
						   explicitly write an inner data header */
						envelopeInfoPtr->envState = ENVSTATE_DATA;
					break;
	
				default:
					assert( NOTREACHED );
				}
			length = stell( &stream );
			sMemDisconnect( &stream );
			if( cryptStatusError( status ) )
				return( status );
			envelopeInfoPtr->bufPos = length;

			/* Reset the segmentation state.  Although PGP doesn't segment 
			   the payload, we still have to reset the state to synchronise 
			   things like payload hashing and encryption.  We also set the 
			   block size mask to all ones if we're not encrypting, since we 
			   can begin and end data segments on arbitrary boundaries */
			envelopeInfoPtr->dataFlags |= ENVDATA_SEGMENTCOMPLETE;
			if( envelopeInfoPtr->usage != ACTION_CRYPT )
				envelopeInfoPtr->blockSizeMask = -1;
			envelopeInfoPtr->lastAction = NULL;

			/* If we're not emitting any inner header, we're done */
			if( envelopeInfoPtr->envState == ENVSTATE_HEADER || \
				( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) )
				{
				envelopeInfoPtr->envState = ENVSTATE_DONE;
				return( CRYPT_OK );
				}
			}
		}

	/* Handle key export actions */
	if( envelopeInfoPtr->envState == ENVSTATE_KEYINFO )
		{
		ACTION_LIST *lastActionPtr;

		/* Export the session key using each of the PKC keys, or write the 
		   derivation information needed to recreate the session key */
		for( lastActionPtr = envelopeInfoPtr->lastAction; 
			 lastActionPtr != NULL; lastActionPtr = lastActionPtr->next )
			{
			void *bufPtr = envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos;
			const int dataLeft = min( envelopeInfoPtr->bufSize - \
									  envelopeInfoPtr->bufPos, 8192 );
			int keyexSize;

			/* Make sure that there's enough room to emit this key exchange 
			   action */
			if( lastActionPtr->encodedSize + 128 > dataLeft )
				{
				status = CRYPT_ERROR_OVERFLOW;
				break;
				}

			/* Emit the key exchange action */
			if( lastActionPtr->action == ACTION_KEYEXCHANGE_PKC )
				status = iCryptExportKeyEx( bufPtr, &keyexSize, dataLeft,
								CRYPT_FORMAT_PGP, envelopeInfoPtr->iCryptContext,
								lastActionPtr->iCryptHandle, CRYPT_UNUSED );
			else
				status = iCryptExportKeyEx( bufPtr, &keyexSize, dataLeft,
								CRYPT_FORMAT_PGP, CRYPT_UNUSED, 
								envelopeInfoPtr->iCryptContext, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				break;
			envelopeInfoPtr->bufPos += keyexSize;
			}
		envelopeInfoPtr->lastAction = lastActionPtr;
		if( cryptStatusError( status ) )
			return( status );

		/* Move on to the next state */
		envelopeInfoPtr->envState = ENVSTATE_ENCRINFO;
		}

	/* Handle encrypted content information */
	if( envelopeInfoPtr->envState == ENVSTATE_ENCRINFO )
		{
		STREAM stream;
		BYTE ivInfoBuffer[ CRYPT_MAX_IVSIZE + 2 ];
		const int dataLeft = min( envelopeInfoPtr->bufSize - \
								  envelopeInfoPtr->bufPos, 8192 );
		int length;

		/* Make sure that there's enough room to emit the encrypted content 
		   header (+4 for slop space) */
		if( dataLeft < PGP_MAX_HEADER_SIZE + PGP_IVSIZE + 2 + 4 )
			return( CRYPT_ERROR_OVERFLOW );

		/* Set up the PGP IV information */
		status = pgpProcessIV( envelopeInfoPtr->iCryptContext, 
							   ivInfoBuffer, PGP_IVSIZE, TRUE, TRUE );
		if( cryptStatusError( status ) )
			return( status );

		/* Write the encrypted content header */
		sMemOpen( &stream, envelopeInfoPtr->buffer + \
						   envelopeInfoPtr->bufPos, dataLeft );
		pgpWritePacketHeader( &stream, PGP_PACKET_ENCR, 
							PGP_IVSIZE + 2 + 1 + \
							pgpSizeofLength( PGP_DATA_HEADER_SIZE + \
											 envelopeInfoPtr->payloadSize ) + \
							PGP_DATA_HEADER_SIZE + \
							envelopeInfoPtr->payloadSize );
		status = swrite( &stream, ivInfoBuffer, PGP_IVSIZE + 2 );
		length = stell( &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		envelopeInfoPtr->bufPos += length;

		/* Make sure that we start a new segment if we try to add any data */
		envelopeInfoPtr->dataFlags |= ENVDATA_SEGMENTCOMPLETE;

		/* Before we can finish we have to push in the inner data header */
		envelopeInfoPtr->envState = ENVSTATE_DATA;
		}

	/* Handle data payload information */
	if( envelopeInfoPtr->envState == ENVSTATE_DATA )
		{
		STREAM stream;
		BYTE headerBuffer[ 64 ];

		/* Make sure that there's enough room to emit the data header (+4 
		   for slop space) */
		if( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos < \
			PGP_MAX_HEADER_SIZE + PGP_DATA_HEADER_SIZE + 4 )
			return( CRYPT_ERROR_OVERFLOW );

		/* Write the payload header.  Since this may be encrypted, we have to
		   do it indirectly via copyToEnvelope() */
		sMemOpen( &stream, headerBuffer, 64 );
		pgpWritePacketHeader( &stream, PGP_PACKET_DATA, 
						PGP_DATA_HEADER_SIZE + envelopeInfoPtr->payloadSize );
		swrite( &stream, PGP_DATA_HEADER, PGP_DATA_HEADER_SIZE );
		if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
			/* There's an absolute data length set, adjust the running total 
			   count by the size of the additional header that's been 
			   prepended */
			envelopeInfoPtr->segmentSize += stell( &stream );
		status = envelopeInfoPtr->copyToEnvelopeFunction( envelopeInfoPtr,
											headerBuffer, stell( &stream ) );
		sMemClose( &stream );
		if( cryptStatusError( status ) )
			return( status );

		/* We've processed the header, if this is signed data we start 
		   hashing from this point.  The PGP RFCs are wrong in this regard, 
		   only the payload is hashed, not the entire packet */
		if( envelopeInfoPtr->usage == ACTION_SIGN )
			envelopeInfoPtr->dataFlags |= ENVDATA_HASHACTIONSACTIVE;

		/* We're finished */
		envelopeInfoPtr->envState = ENVSTATE_DONE;
		}

	return( CRYPT_OK );
	}

/* Output as much of the postamble as possible into the envelope buffer */

static int emitPostamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	int sigBufSize, sigSize, status;

	/* Before we can emit the trailer we need to flush any remaining data
	   from internal buffers */
	if( envelopeInfoPtr->envState == ENVSTATE_NONE )
		{
		status = envelopeInfoPtr->copyToEnvelopeFunction( envelopeInfoPtr, 
														  ( BYTE * ) "", 0 );
		if( cryptStatusError( status ) )
			return( status );
		envelopeInfoPtr->envState = ENVSTATE_FLUSHED;
		}

	/* The only PGP packet that has a trailer is signed data using the new
	   (post-2.x) one-pass signature packet, if we're not signing data we can
	   exit now */
	if( envelopeInfoPtr->usage != ACTION_SIGN )
		{
		/* We're done */
		envelopeInfoPtr->envState = ENVSTATE_DONE;
		return( CRYPT_OK );
		}

	/* Check whether there's enough room left in the buffer to emit the 
	   signature directly into it.  Since sigs are fairly small (a few 
	   hundred bytes), we always require enough room in the buffer and don't 
	   bother with any overflow handling via the auxBuffer */
	sigBufSize = min( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos, 
					  8192 );
	if( envelopeInfoPtr->postActionList->encodedSize + 64 > sigBufSize )
		return( CRYPT_ERROR_OVERFLOW );

	/* Sign the data */
	status = iCryptCreateSignatureEx( envelopeInfoPtr->buffer + \
									  envelopeInfoPtr->bufPos, &sigSize, 
									  sigBufSize, CRYPT_FORMAT_PGP, 
									  envelopeInfoPtr->postActionList->iCryptHandle, 
									  envelopeInfoPtr->actionList->iCryptHandle,
									  CRYPT_UNUSED, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( status );
	envelopeInfoPtr->bufPos += sigSize;

	/* Now that we've written the final data, set the end-of-segment-data 
	   pointer to the end of the data in the buffer so that 
	   copyFromEnvelope() can copy out the remaining data */
	envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->bufPos;
	envelopeInfoPtr->envState = ENVSTATE_DONE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

void initPGPEnveloping( ENVELOPE_INFO *envelopeInfoPtr )
	{
	/* Set the access method pointers */
	envelopeInfoPtr->processPreambleFunction = emitPreamble;
	envelopeInfoPtr->processPostambleFunction = emitPostamble;
	envelopeInfoPtr->checkCryptAlgo = checkCryptAlgo;
	envelopeInfoPtr->checkHashAlgo = checkHashAlgo;

	/* Set up the processing state information */
	envelopeInfoPtr->envState = ENVSTATE_NONE;

	/* Remember the current default settings for use with the envelope.  
	   Since the PGP algorithms represent only a subset of what's available, 
	   we have to drop back to fixed values if the caller has selected 
	   something exotic */
	krnlSendMessage( envelopeInfoPtr->ownerHandle, 
					 IMESSAGE_GETATTRIBUTE, &envelopeInfoPtr->defaultHash, 
					 CRYPT_OPTION_ENCR_HASH );
	if( cryptlibToPgpAlgo( envelopeInfoPtr->defaultHash ) == PGP_ALGO_NONE )
		envelopeInfoPtr->defaultHash = CRYPT_ALGO_SHA;
	krnlSendMessage( envelopeInfoPtr->ownerHandle, 
					 IMESSAGE_GETATTRIBUTE, &envelopeInfoPtr->defaultAlgo, 
					 CRYPT_OPTION_ENCR_ALGO );
	if( cryptlibToPgpAlgo( envelopeInfoPtr->defaultAlgo ) == PGP_ALGO_NONE )
		envelopeInfoPtr->defaultAlgo = CRYPT_ALGO_3DES;
	envelopeInfoPtr->defaultMAC = CRYPT_ALGO_NONE;

	/* Turn off segmentation of the envelope payload.  PGP has a single 
	   length at the start of the data and doesn't segment the payload */
	envelopeInfoPtr->dataFlags |= ENVDATA_NOSEGMENT;
	}
#endif /* USE_PGP */
