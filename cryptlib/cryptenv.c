/****************************************************************************
*																			*
*						cryptlib Enveloping Routines						*
*					  Copyright Peter Gutmann 1996-2003						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "envelope.h"
#else
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

#ifdef USE_ENVELOPES

/* The default size for the envelope buffer.  On 16-bit systems they're
   smaller because of memory and int size limitations */

#if defined( CONFIG_CONSERVE_MEMORY )
  #define DEFAULT_BUFFER_SIZE		8192
#elif INT_MAX <= 32767
  #define DEFAULT_BUFFER_SIZE		16384
#else
  #define DEFAULT_BUFFER_SIZE		32768
#endif /* OS-specific envelope size defines */

/* When pushing and popping data, overflow and underflow errors can be
   recovered from by adding or removing data, so we don't retain the error
   state for these error types */

#define isRecoverableError( status ) \
		( ( status ) == CRYPT_ERROR_OVERFLOW || \
		  ( status ) == CRYPT_ERROR_UNDERFLOW )

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Instantiate a cert chain from a collection of certs */

static int instantiateCertChain( const ENVELOPE_INFO *envelopeInfoPtr,
								 CONTENT_LIST *contentListItem )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( contentListItem->flags & CONTENTLIST_ISSIGOBJ );

	/* Instantiate the cert chain.  Since this isn't a true cert chain (in 
	   the sense of being degenerate PKCS #7 SignedData) but only a 
	   context-tagged SET OF Certificate, we notify the cert management code 
	   of this when it performs the import */
	setMessageCreateObjectIndirectInfo( &createInfo, 
				envelopeInfoPtr->auxBuffer, envelopeInfoPtr->auxBufSize,
				CRYPT_ICERTTYPE_CMS_CERTSET );
	if( contentListItem->issuerAndSerialNumber == NULL )
		{
		createInfo.arg2 = CRYPT_IKEYID_KEYID;
		createInfo.strArg2 = contentListItem->keyID;
		createInfo.strArgLen2 = contentListItem->keyIDsize;
		}
	else
		{
		createInfo.arg2 = CRYPT_IKEYID_ISSUERANDSERIALNUMBER;
		createInfo.strArg2 = contentListItem->issuerAndSerialNumber;
		createInfo.strArgLen2 = contentListItem->issuerAndSerialNumberSize;
		}
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		contentListItem->clSigInfo.iSigCheckKey = createInfo.cryptHandle;
	return( status );
	}

/* Move the envelope component cursor */

static int moveCursor( ENVELOPE_INFO *envelopeInfoPtr, const int value )
	{
	if( envelopeInfoPtr->contentList == NULL )
		return( CRYPT_ERROR_NOTFOUND );	/* Nothing to move the cursor to */

	switch( value )
		{
		case CRYPT_CURSOR_FIRST:
			envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
			break;

		case CRYPT_CURSOR_PREVIOUS:
			if( envelopeInfoPtr->contentListCurrent == NULL || \
				envelopeInfoPtr->contentListCurrent == envelopeInfoPtr->contentList )
				return( CRYPT_ERROR_NOTFOUND );
			else
				{
				CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentList;

				/* Find the previous element in the list */
				while( contentListPtr->next != envelopeInfoPtr->contentListCurrent )
					contentListPtr = contentListPtr->next;
				envelopeInfoPtr->contentListCurrent = contentListPtr;
				}
			break;

		case CRYPT_CURSOR_NEXT:
			if( envelopeInfoPtr->contentListCurrent == NULL || \
				envelopeInfoPtr->contentListCurrent->next == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentListCurrent->next;
			break;

		case CRYPT_CURSOR_LAST:
			envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
			while( envelopeInfoPtr->contentListCurrent->next != NULL )
				envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentListCurrent->next;
			break;

		default:
			return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Envelope Attribute Handling Functions				*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

static int exitError( ENVELOPE_INFO *envelopeInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  const CRYPT_ERRTYPE_TYPE errorType, const int status )
	{
	setErrorInfo( envelopeInfoPtr, errorLocus, errorType );
	return( status );
	}

static int exitErrorInited( ENVELOPE_INFO *envelopeInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( envelopeInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT, 
					   CRYPT_ERROR_INITED ) );
	}

static int exitErrorNotInited( ENVELOPE_INFO *envelopeInfoPtr,
							   const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( envelopeInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT, 
					   CRYPT_ERROR_NOTINITED ) );
	}

static int exitErrorNotFound( ENVELOPE_INFO *envelopeInfoPtr,
							  const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( envelopeInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT, 
					   CRYPT_ERROR_NOTFOUND ) );
	}

/* Handle data sent to or read from an envelope object */

static int processGetAttribute( ENVELOPE_INFO *envelopeInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	int *valuePtr = ( int * ) messageDataPtr, status;

	/* Generic attributes are valid for all envelope types */
	if( messageValue == CRYPT_ATTRIBUTE_BUFFERSIZE )
		{
		*valuePtr = envelopeInfoPtr->bufSize;
		return( CRYPT_OK );
		}
	if( messageValue == CRYPT_ATTRIBUTE_ERRORTYPE )
		{
		*valuePtr = envelopeInfoPtr->errorType;
		return( CRYPT_OK );
		}
	if( messageValue == CRYPT_ATTRIBUTE_ERRORLOCUS )
		{
		*valuePtr = envelopeInfoPtr->errorLocus;
		return( CRYPT_OK );
		}

	/* If we're de-enveloping PGP data, make sure that the attribute is valid 
	   for PGP envelopes.  We can't perform this check via the ACLs because 
	   the data type isn't known at envelope creation time, so there's a 
	   single generic de-envelope type for which the ACLs allow the union of 
	   all de-enveloping attribute types.  The following check weeds out the 
	   ones that don't work for PGP */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
		messageValue == CRYPT_ENVINFO_SIGNATURE_EXTRADATA )
		return( CRYPT_ARGERROR_VALUE );

	/* Make sure that the attribute is valid for this envelope type and state */
	switch( messageValue )
		{
		case CRYPT_OPTION_ENCR_ALGO:
		case CRYPT_OPTION_ENCR_HASH:
		case CRYPT_OPTION_ENCR_MAC:
			/* Algorithm types are valid only for enveloping */
			if( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE )
				return( CRYPT_ARGERROR_OBJECT );
			break;
					
		case CRYPT_ENVINFO_CURRENT_COMPONENT:
		case CRYPT_ENVINFO_SIGNATURE_RESULT:
		case CRYPT_ENVINFO_SIGNATURE:
		case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
			/* The signature key and extra data is read-only for de-
			   enveloping, write-only for enveloping, which can't be checked 
			   by the more general kernel checks (the current-component and 
			   sig-result attributes are de-enveloping only, so they are 
			   checked) */
			if( !( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) )
				return( CRYPT_ARGERROR_OBJECT );

			/* The following check isn't strictly necessary since we can get 
			   some information as soon as it's available, but it leads to 
			   less confusion (for example without this check we can get 
			   signer info long before we can get the signature results, 
			   which could be misinterpreted to mean the signature is bad) 
			   and forces the caller to do things cleanly */
			if( envelopeInfoPtr->usage == ACTION_SIGN && \
				envelopeInfoPtr->state != STATE_FINISHED )
				return( CRYPT_ERROR_INCOMPLETE );

			/* We're querying something that resides in the content list, 
			   make sure that there's a content list present.  If it's 
			   present but nothing is selected, select the first entry */
			if( envelopeInfoPtr->contentListCurrent == NULL )
				{
				if( envelopeInfoPtr->contentList == NULL )
					return( exitErrorNotFound( envelopeInfoPtr, 
											   messageValue ) );
				envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
				}
			break;

#if 0	/* Unused, removed 9/9/03 */
		case CRYPT_IATTRIBUTE_PAYLOADSIZE:
			/* In order to determine the available payload size, we must be 
			   in the finished state (envelope flush successfully processed) 
			   so that all the data is available */
			if( envelopeInfoPtr->state != STATE_FINISHED )
				return( CRYPT_ERROR_INCOMPLETE );

			/* We can only determine the payload size if we're using a 
			   processing mode where this is possible */
			if( envelopeInfoPtr->usage != ACTION_SIGN && \
				envelopeInfoPtr->usage != ACTION_CRYPT )
				return( CRYPT_ERROR_NOTFOUND );
			break;
#endif /* 0 */

		default:
			assert( messageValue == CRYPT_ENVINFO_COMPRESSION || \
					messageValue == CRYPT_ENVINFO_CONTENTTYPE || \
					messageValue == CRYPT_ENVINFO_DETACHEDSIGNATURE || \
					messageValue == CRYPT_IATTRIBUTE_ATTRONLY );
		}

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_OPTION_ENCR_ALGO:
			if( envelopeInfoPtr->defaultAlgo == CRYPT_ALGO_NONE )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_OPTION_ENCR_ALGO ) );
			*valuePtr = envelopeInfoPtr->defaultAlgo;
			return( CRYPT_OK );

		case CRYPT_OPTION_ENCR_HASH:
			if( envelopeInfoPtr->defaultHash == CRYPT_ALGO_NONE )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_OPTION_ENCR_HASH ) );
			*valuePtr = envelopeInfoPtr->defaultHash;
			return( CRYPT_OK );

		case CRYPT_OPTION_ENCR_MAC:
			if( envelopeInfoPtr->defaultMAC == CRYPT_ALGO_NONE )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_OPTION_ENCR_MAC ) );
			*valuePtr = envelopeInfoPtr->defaultMAC;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_COMPRESSION:
			if( envelopeInfoPtr->usage == ACTION_NONE )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_ENVINFO_COMPRESSION ) );
			*valuePtr = ( envelopeInfoPtr->usage == ACTION_COMPRESS ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_CURRENT_COMPONENT:
			{
			CONTENT_LIST *contentListItem = \
								envelopeInfoPtr->contentListCurrent;
			MESSAGE_KEYMGMT_INFO getkeyInfo;

			assert( contentListItem != NULL );

			/* If we need something other than a private key or we need a
			   private key but there's no keyset present to fetch it from,
			   just report what we need and exit */
			if( contentListItem->envInfo != CRYPT_ENVINFO_PRIVATEKEY || \
				envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR )
				{
				*valuePtr = contentListItem->envInfo;
				return( CRYPT_OK );
				}

			/* There's a decryption keyset available, try and get the
			   required key from it.  Since we're accessing the key by 
			   (unique) key ID, there's no real need to specify a preference 
			   for encryption keys.

			   Unlike sig.check keyset access, we retry the access every 
			   time we're called because we may be talking to a device that 
			   has a trusted authentication path which is outside our 
			   control, so that the first read fails if the user hasn't 
			   entered their PIN but a second read once they've entered it 
			   will succeed */
			if( contentListItem->issuerAndSerialNumber == NULL )
				{
				setMessageKeymgmtInfo( &getkeyInfo, 
								( contentListItem->formatType == CRYPT_FORMAT_PGP ) ? \
								CRYPT_IKEYID_PGPKEYID : CRYPT_IKEYID_KEYID, 
								contentListItem->keyID,
								contentListItem->keyIDsize, NULL, 0,
								KEYMGMT_FLAG_NONE );
				}
			else
				{
				setMessageKeymgmtInfo( &getkeyInfo, 
								CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								contentListItem->issuerAndSerialNumber,
								contentListItem->issuerAndSerialNumberSize,
								NULL, 0, KEYMGMT_FLAG_NONE );
				}
			status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
									  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
									  KEYMGMT_ITEM_PRIVATEKEY );

			/* If we managed to get the private key (either bcause it wasn't
			   protected by a password if it's in a keyset or because it came
			   from a device), push it into the envelope.  If the call
			   succeeds, this will import the session key and delete the
			   required-information list */
			if( cryptStatusOK( status ) )
				{
				status = envelopeInfoPtr->addInfo( envelopeInfoPtr,
												   CRYPT_ENVINFO_PRIVATEKEY,
												   &getkeyInfo.cryptHandle, 0 );
				krnlSendNotifier( getkeyInfo.cryptHandle,
								  IMESSAGE_DECREFCOUNT );
				}

			/* If we got the key, there's nothing else needed.  If we didn't,
			   we still return an OK status since the caller is asking us for
			   the resource which is required and not the status of any
			   background operation that was performed while trying to obtain
			   it */
			*valuePtr = cryptStatusError( status ) ? \
							envelopeInfoPtr->contentListCurrent->envInfo : \
							CRYPT_ATTRIBUTE_NONE;
			return( CRYPT_OK );
			}

		case CRYPT_ENVINFO_CONTENTTYPE:
			if( envelopeInfoPtr->contentType == CRYPT_CONTENT_NONE )
				return( exitErrorNotFound( envelopeInfoPtr, 
										   CRYPT_ENVINFO_CONTENTTYPE ) );
			*valuePtr = envelopeInfoPtr->contentType;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_DETACHEDSIGNATURE:
			/* If this isn't signed data or we haven't sorted out the content
			   details yet, we don't know whether it's a detached sig or
			   not */
			if( envelopeInfoPtr->usage != ACTION_SIGN || \
				envelopeInfoPtr->contentType == CRYPT_CONTENT_NONE )
				return( exitErrorNotFound( envelopeInfoPtr, 
										   CRYPT_ENVINFO_DETACHEDSIGNATURE ) );
			*valuePtr = ( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_SIGNATURE_RESULT:
			{
			CRYPT_HANDLE iCryptHandle;
			CONTENT_LIST *contentListItem = \
								envelopeInfoPtr->contentListCurrent;
			const CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;
			MESSAGE_KEYMGMT_INFO getkeyInfo;

			assert( contentListItem != NULL );

			/* Make sure that the content list item is of the appropriate 
			   type, and if we've already done this one don't process it a 
			   second time.  This check is also performed by the addInfo() 
			   code, but we duplicate it here (just for the signature-result 
			   attribute) to avoid having to do an unnecessary key fetch for 
			   non-CMS signatures */
			if( contentListItem->envInfo != CRYPT_ENVINFO_SIGNATURE )
				return( exitErrorNotFound( envelopeInfoPtr, 
										   CRYPT_ENVINFO_SIGNATURE_RESULT ) );
			if( contentListItem->flags & CONTENTLIST_PROCESSED )
				{
				*valuePtr = sigInfo->processingResult;
				return( CRYPT_OK );
				}

			/* If there's an encoded cert chain present and it hasn't been
			   instantiated as a cert object yet, instantiate it now.  We
			   don't check the return value since a failure isn't fatal, we
			   can still perform the sig.check with a key pulled from a 
			   keyset */
			if( sigInfo->iSigCheckKey == CRYPT_ERROR && \
				envelopeInfoPtr->auxBuffer != NULL )
				instantiateCertChain( envelopeInfoPtr, contentListItem );

			/* If we have a key instantiated from a cert chain, use that to
			   check the signature.  In theory we could also be re-using the 
			   key from an earlier, not-completed check, however this is only 
			   retained if the check succeeds (to allow a different key to be 
			   tried if the check fails), so in practice this never occurs */
			if( sigInfo->iSigCheckKey != CRYPT_ERROR )
				{
				*valuePtr = envelopeInfoPtr->addInfo( envelopeInfoPtr,
										CRYPT_ENVINFO_SIGNATURE, 
										&sigInfo->iSigCheckKey, TRUE );
				return( CRYPT_OK );
				}

			/* We don't have a sig.check key available (for example from a 
			   CMS cert chain), make sure that there's a keyset available to 
			   pull the key from and get the key from it */
			if( envelopeInfoPtr->iSigCheckKeyset == CRYPT_ERROR )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_ENVINFO_KEYSET_SIGCHECK ) );

			/* Try and get the key.  Since we're accessing the key by 
			   (unique) key ID, there's no real need to specify a preference 
			   for encryption keys */
			if( contentListItem->issuerAndSerialNumber == NULL )
				{
				setMessageKeymgmtInfo( &getkeyInfo, 
							( contentListItem->formatType == CRYPT_FORMAT_PGP ) ? \
							CRYPT_IKEYID_PGPKEYID : CRYPT_IKEYID_KEYID, 
							contentListItem->keyID,
							contentListItem->keyIDsize, NULL, 0,
							KEYMGMT_FLAG_NONE );
				}
			else
				{
				setMessageKeymgmtInfo( &getkeyInfo,
							CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
							contentListItem->issuerAndSerialNumber,
							contentListItem->issuerAndSerialNumberSize,
							NULL, 0, KEYMGMT_FLAG_NONE );
				}
			status = krnlSendMessage( envelopeInfoPtr->iSigCheckKeyset,
									  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
									  KEYMGMT_ITEM_PUBLICKEY );
			if( cryptStatusError( status ) )
				return( status );
			iCryptHandle = getkeyInfo.cryptHandle;

			/* Push the public key into the envelope, which performs the 
			   signature check.  Adding the key increments its reference 
			   count since the key is usually user-supplied and we need to 
			   keep a reference for use by the envelope, however since the 
			   key we're using here is an internal-use-only key we don't 
			   want to do this so we decrement it again after it's been 
			   added */
			*valuePtr = envelopeInfoPtr->addInfo( envelopeInfoPtr,
								CRYPT_ENVINFO_SIGNATURE, &iCryptHandle, TRUE );
			krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );

			/* If the key wasn't used for the sig check (i.e. it wasn't 
			   stored in the content list for later use, which means it isn't 
			   needed any more), discard it */
			if( sigInfo->iSigCheckKey == CRYPT_ERROR )
				krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
			return( CRYPT_OK );
			}

		case CRYPT_ENVINFO_SIGNATURE:
			{
			CONTENT_LIST *contentListItem = \
								envelopeInfoPtr->contentListCurrent;
			CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;
			MESSAGE_CREATEOBJECT_INFO createInfo;
			RESOURCE_DATA msgData;
			BYTE certData[ 2048 ], *certDataPtr = certData;

			assert( contentListItem != NULL );

			/* If there's no signing key present, try and instantiate it 
			   from an attached cert chain */
			if( sigInfo->iSigCheckKey == CRYPT_ERROR )
				{
				if( envelopeInfoPtr->auxBuffer == NULL )
					/* There's no attached cert chain to recover the signing 
					   key from, we can't go any further */
					return( exitErrorNotFound( envelopeInfoPtr, 
											   CRYPT_ENVINFO_SIGNATURE ) );
				status = instantiateCertChain( envelopeInfoPtr, 
											   contentListItem );
				if( cryptStatusError( status ) )
					return( exitError( envelopeInfoPtr, 
									   CRYPT_ENVINFO_SIGNATURE, 
									   CRYPT_ERRTYPE_ATTR_VALUE, status ) );
				}

			/* If we instantiated the sig-check key ourselves (either from a 
			   keyset or from envelope data) rather than having it supplied
			   externally, we're done */
			if( !( contentListItem->flags & CONTENTLIST_EXTERNALKEY ) )
				{
				krnlSendNotifier( sigInfo->iSigCheckKey, 
								  IMESSAGE_INCREFCOUNT );
				*valuePtr = sigInfo->iSigCheckKey;
				return( CRYPT_OK );
				}

			/* The sig check key was externally supplied by the caller.  If 
			   they added a private key+cert combination as the sig.check 
			   key then this will return a supposed signature-check cert 
			   that actually has private-key capabilities.  Even adding a 
			   simple cert (+public key context for the sig.check) can be 
			   dangerous since it can act as a subliminal channel if it's 
			   passed on to a different user (although exactly how this would 
			   be exploitable is another question entirely).  To avoid this 
			   problem, we completely isolate the added sig.check key by 
			   exporting it and re-importing it as a new certificate object */
			setMessageData( &msgData, certDataPtr, 2048 );
			status = krnlSendMessage( sigInfo->iSigCheckKey,
									  IMESSAGE_CRT_EXPORT, &msgData,
									  CRYPT_CERTFORMAT_CERTCHAIN );
			if( status == CRYPT_ERROR_OVERFLOW )
				{
				if( ( certDataPtr = clAlloc( "processGetAttribute", \
											 msgData.length ) ) == NULL )
					return( CRYPT_ERROR_MEMORY );
				setMessageData( &msgData, certDataPtr, msgData.length );
				status = krnlSendMessage( sigInfo->iSigCheckKey,
										  IMESSAGE_CRT_EXPORT, &msgData,
										  CRYPT_CERTFORMAT_CERTCHAIN );
				}
			if( cryptStatusOK( status ) )
				{
				setMessageCreateObjectIndirectInfo( &createInfo, certDataPtr,
													msgData.length,
													CRYPT_CERTTYPE_CERTCHAIN );
				status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
										  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
										  &createInfo, OBJECT_TYPE_CERTIFICATE );
				}
			if( certDataPtr != certData )
				clFree( "processGetAttribute", certDataPtr );
			if( cryptStatusError( status ) )
				return( exitError( envelopeInfoPtr, 
								   CRYPT_ENVINFO_SIGNATURE, 
								   CRYPT_ERRTYPE_ATTR_VALUE, 
								   status ) );

			/* We've created a new instantiation of the sig.check key which 
			   is distinct from the externally-supplied original, return it 
			   to the caller */
			krnlSendNotifier( sigInfo->iSigCheckKey, IMESSAGE_DECREFCOUNT );
			*valuePtr = sigInfo->iSigCheckKey = createInfo.cryptHandle;
			return( CRYPT_OK );
			}

		case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
			{
			CRYPT_HANDLE iCryptHandle;
			CONTENT_LIST *contentListItem = \
								envelopeInfoPtr->contentListCurrent;

			assert( contentListItem != NULL );

			/* Make sure that there's extra data present */
			iCryptHandle = contentListItem->clSigInfo.iExtraData;
			if( iCryptHandle == CRYPT_ERROR )
				return( exitErrorNotFound( envelopeInfoPtr, 
									CRYPT_ENVINFO_SIGNATURE_EXTRADATA ) );

			/* Return it to the caller */
			krnlSendNotifier( iCryptHandle, IMESSAGE_INCREFCOUNT );
			*valuePtr = iCryptHandle;
			return( CRYPT_OK );
			}

#if 0	/* Unused, removed 9/9/03 */
		case CRYPT_IATTRIBUTE_PAYLOADSIZE:
			/* This is an internal attribute used by high-level cryptlib 
			   functions that use CMS as their native data format.  These
			   typically push the entire data quantity into an envelope
			   at once and then need to know how much data will be produced
			   to write to an output stream */
			*valuePtr = envelopeInfoPtr->bufPos;
			return( CRYPT_OK );
#endif /* 0 */

		case CRYPT_IATTRIBUTE_ATTRONLY:
			/* If this isn't signed data, we don't know whether it's an 
			   attributes-only message or not */
			if( envelopeInfoPtr->usage != ACTION_SIGN )
				return( exitErrorNotFound( envelopeInfoPtr, 
										   CRYPT_IATTRIBUTE_ATTRONLY ) );
			*valuePtr = ( envelopeInfoPtr->flags & ENVELOPE_ATTRONLY ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processGetAttributeS( ENVELOPE_INFO *envelopeInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	CONTENT_LIST *contentListItem;
	int status;

	/* If we're querying something that resides in the content list, make
	   sure there's a content list present.  If it's present but nothing is
	   selected, select the first entry */
	if( messageValue == CRYPT_ENVINFO_PRIVATEKEY_LABEL && \
		envelopeInfoPtr->contentListCurrent == NULL )
		{
		if( envelopeInfoPtr->contentList == NULL )
			return( exitErrorNotFound( envelopeInfoPtr, 
									   CRYPT_ENVINFO_PRIVATEKEY_LABEL ) );
		envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
		}

	/* Generic attributes are valid for all envelope types */
	if( messageValue == CRYPT_ENVINFO_PRIVATEKEY_LABEL )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		char label[ CRYPT_MAX_TEXTSIZE ];

		/* Make sure that the current required resource is a private key and
		   that there's a keyset available to pull the key from */
		contentListItem = envelopeInfoPtr->contentListCurrent;
		if( contentListItem->envInfo != CRYPT_ENVINFO_PRIVATEKEY )
			return( exitErrorNotFound( envelopeInfoPtr, 
									   CRYPT_ENVINFO_PRIVATEKEY_LABEL ) );
		if( envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR )
			return( exitErrorNotInited( envelopeInfoPtr, 
										CRYPT_ENVINFO_KEYSET_DECRYPT ) );

		/* Try and get the key label information.  Since we're accessing the 
		   key by (unique) key ID, there's no real need to specify a 
		   preference for encryption keys */
		if( contentListItem->issuerAndSerialNumber == NULL )
			{
			setMessageKeymgmtInfo( &getkeyInfo, 
								   ( contentListItem->formatType == CRYPT_FORMAT_PGP ) ? \
								   CRYPT_IKEYID_PGPKEYID : CRYPT_IKEYID_KEYID, 
								   contentListItem->keyID,
								   contentListItem->keyIDsize,
								   label, CRYPT_MAX_TEXTSIZE,
								   KEYMGMT_FLAG_LABEL_ONLY );
			}
		else
			{
			setMessageKeymgmtInfo( &getkeyInfo, 
								   CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								   contentListItem->issuerAndSerialNumber,
								   contentListItem->issuerAndSerialNumberSize,
								   label, CRYPT_MAX_TEXTSIZE,
								   KEYMGMT_FLAG_LABEL_ONLY );
			}
		status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
								  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
								  KEYMGMT_ITEM_PRIVATEKEY );
		if( cryptStatusOK( status ) )
			return( attributeCopy( messageDataPtr, getkeyInfo.auxInfo,
								   getkeyInfo.auxInfoLength ) );
		return( status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttribute( ENVELOPE_INFO *envelopeInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	MESSAGE_CHECK_TYPE checkType = MESSAGE_CHECK_NONE;
	ACTION_TYPE usage = ACTION_NONE;
	static const struct {
		const CRYPT_ATTRIBUTE_TYPE type;	/* Attribute type */
		const ACTION_TYPE usage;			/* Corresponding usage type */
		const MESSAGE_CHECK_TYPE checkType;	/*  and check type */
		} checkTable[] = {
#ifdef USE_COMPRESSION
		{ CRYPT_ENVINFO_COMPRESSION, ACTION_COMPRESS, MESSAGE_CHECK_NONE },
#endif /* USE_COMPRESSION */
		{ CRYPT_ENVINFO_MAC, ACTION_MAC, MESSAGE_CHECK_MAC },
		{ CRYPT_ENVINFO_KEY, ACTION_CRYPT, MESSAGE_CHECK_CRYPT },
		{ CRYPT_ENVINFO_PUBLICKEY, ACTION_CRYPT, MESSAGE_CHECK_PKC_ENCRYPT },
		{ CRYPT_ENVINFO_PRIVATEKEY, ACTION_CRYPT, MESSAGE_CHECK_PKC_DECRYPT },
		{ CRYPT_ENVINFO_HASH, ACTION_SIGN, MESSAGE_CHECK_HASH },
		{ CRYPT_ENVINFO_TIMESTAMP_AUTHORITY, ACTION_SIGN, MESSAGE_CHECK_NONE },
		{ CRYPT_ENVINFO_DETACHEDSIGNATURE, ACTION_SIGN, MESSAGE_CHECK_NONE },
		{ CRYPT_IATTRIBUTE_INCLUDESIGCERT, ACTION_SIGN, MESSAGE_CHECK_NONE },
		{ CRYPT_IATTRIBUTE_ATTRONLY, ACTION_SIGN, MESSAGE_CHECK_NONE },
		{ CRYPT_ATTRIBUTE_NONE, ACTION_NONE }
		};
	const int value = *( int * ) messageDataPtr;
	int i, status;

	/* If it's an initialisation message, there's nothing to do */
	if( messageValue == CRYPT_IATTRIBUTE_INITIALISED )
		return( CRYPT_OK );

	/* Generic attributes are valid for all envelope types */
	if( messageValue == CRYPT_ATTRIBUTE_BUFFERSIZE )
		{
		envelopeInfoPtr->bufSize = value;
		return( CRYPT_OK );
		}

	/* If it's meta-information, process it now */
	if( messageValue == CRYPT_ENVINFO_CURRENT_COMPONENT )
		return( moveCursor( envelopeInfoPtr, value ) );

	/* In general we can't add new enveloping information once we've started
	   processing data */
	if( messageValue != CRYPT_ENVINFO_CURRENT_COMPONENT && \
		envelopeInfoPtr->state != STATE_PREDATA )
		{
		/* We can't add new information once we've started enveloping */
		if( !( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) )
			return( CRYPT_ERROR_INITED );

		/* We can only add signature check information once we've started
		   de-enveloping */
		if( messageValue != CRYPT_ENVINFO_SIGNATURE )
			return( CRYPT_ERROR_INITED );
		}

	/* If we're de-enveloping PGP data, make sure that the attribute is 
	   valid for PGP envelopes.  We can't perform this check via the ACLs 
	   because the data type isn't known at envelope creation time, so 
	   there's a single generic de-envelope type for which the ACLs allow 
	   the union of all de-enveloping attribute types.  The following check 
	   weeds out the ones that don't work for PGP */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		{
		if( messageValue == CRYPT_OPTION_ENCR_MAC || \
			messageValue == CRYPT_ENVINFO_MAC || \
			messageValue == CRYPT_ENVINFO_KEY || \
			messageValue == CRYPT_ENVINFO_SESSIONKEY )
			return( CRYPT_ARGERROR_VALUE );
		if( messageValue == CRYPT_ENVINFO_HASH && \
			!( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) )
			/* We can add a hash if we're creating a detached signature */
			return( CRYPT_ARGERROR_VALUE );
		}

	/* Since the information may not be used for quite some time after it's
	   added, we do some preliminary checking here to allow us to return an
	   error code immediately rather than from some deeply-buried function an
	   indeterminate time in the future.  Since much of the checking is
	   similar, we use a table-driven check for most types and fall back to
	   custom checking for special cases */
	for( i = 0; checkTable[ i ].type != ACTION_NONE; i++ )
		if( checkTable[ i ].type == messageValue )
			{
			if( envelopeInfoPtr->usage != ACTION_NONE && \
				envelopeInfoPtr->usage != checkTable[ i ].usage )
				return( exitErrorInited( envelopeInfoPtr, messageValue ) );
			usage = checkTable[ i ].usage;
			checkType = checkTable[ i ].checkType;
			break;
			}
	if( usage == ACTION_NONE )
		switch( messageValue )
			{
			case CRYPT_OPTION_ENCR_ALGO:
				if( cryptStatusError( \
						envelopeInfoPtr->checkCryptAlgo( value, 
								isStreamCipher( value ) ? CRYPT_MODE_OFB : \
								( envelopeInfoPtr->type == CRYPT_FORMAT_PGP ) ? \
								CRYPT_MODE_CFB : CRYPT_MODE_CBC ) ) )
					return( CRYPT_ARGERROR_VALUE );
				envelopeInfoPtr->defaultAlgo = value;
				return( CRYPT_OK );

			case CRYPT_OPTION_ENCR_HASH:
				if( cryptStatusError( \
						envelopeInfoPtr->checkHashAlgo( value ) ) )
					return( CRYPT_ARGERROR_VALUE );
				envelopeInfoPtr->defaultHash = value;
				return( CRYPT_OK );

			case CRYPT_OPTION_ENCR_MAC:
				if( cryptStatusError( \
						envelopeInfoPtr->checkHashAlgo( value ) ) )
					return( CRYPT_ARGERROR_VALUE );
				envelopeInfoPtr->defaultMAC = value;
				return( CRYPT_OK );

			case CRYPT_ENVINFO_DATASIZE:
				if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_DATASIZE ) );
				break;

			case CRYPT_ENVINFO_CONTENTTYPE:
				/* Exactly what is supposed to happen when PGP is asked to 
				   sign non-plain-data is ill-defined.  No command-line PGP 
				   option will generate this type of message, and the RFCs 
				   don't specify the behaviour (in fact RFC 1991's 
				   description of PGP signing is completely wrong).  In 
				   practice PGP hashes and signs the payload contents of a 
				   PGP literal data packet, however if there are extra layers 
				   of processing between the signing and literal packets (eg 
				   compression or encryption), what gets hashed isn't 
				   specified.  If it's always the payload of the final 
				   (literal) data packet, we'd have to be able to burrow down 
				   through arbitrary amounts of further data and processing 
				   in order to get to the payload data to hash (this also 
				   makes things like mail gateways that only allow signed 
				   messages through infeasible unless the gateway holds 
				   everyone's private key in order to get at the plaintext to 
				   hash).  Because of this problem, we disallow any attempts 
				   to set a content-type other than plain data if we're 
				   signing a PGP-format message */
				if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
					envelopeInfoPtr->usage == ACTION_SIGN && \
					value != CRYPT_CONTENT_DATA )
					return( CRYPT_ARGERROR_VALUE );

				/* For user-friendliness we allow overwriting a given content
				   type with the same type, which is useful for cases when
				   cryptlib automatically presets the type based on other
				   information */
				if( envelopeInfoPtr->contentType && \
					envelopeInfoPtr->contentType != value )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_CONTENTTYPE ) );
				break;

			case CRYPT_ENVINFO_SESSIONKEY:
				checkType = MESSAGE_CHECK_CRYPT;
				if( envelopeInfoPtr->usage != ACTION_NONE && \
					!( ( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) && \
					   envelopeInfoPtr->usage == ACTION_CRYPT ) )
					/* On de-enveloping the usage is set by the enveloped data
					   format, so setting a session key when the usage is
					   already set to encryption isn't an error */
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_SESSIONKEY ) );
				usage = ACTION_CRYPT;
				break;

			case CRYPT_ENVINFO_SIGNATURE:
				checkType = \
					( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) ? \
						MESSAGE_CHECK_PKC_SIGCHECK : MESSAGE_CHECK_PKC_SIGN;
				if( envelopeInfoPtr->usage != ACTION_NONE && \
					envelopeInfoPtr->usage != ACTION_SIGN )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_SIGNATURE ) );
				if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
					envelopeInfoPtr->contentType == CRYPT_CONTENT_DATA )
					/* See the long comment for CRYPT_ENVINFO_CONTENTTYPE */
					return( CRYPT_ARGERROR_VALUE );
				usage = ACTION_SIGN;
				break;

			case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
				if( envelopeInfoPtr->type != CRYPT_FORMAT_CMS && \
					envelopeInfoPtr->type != CRYPT_FORMAT_SMIME )
					return( CRYPT_ARGERROR_VALUE );
				if( envelopeInfoPtr->usage != ACTION_NONE && \
					envelopeInfoPtr->usage != ACTION_SIGN )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_SIGNATURE_EXTRADATA ) );
				break;

			case CRYPT_ENVINFO_ORIGINATOR:
				checkType = MESSAGE_CHECK_PKC_KA_EXPORT;
				if( envelopeInfoPtr->usage != ACTION_NONE && \
					envelopeInfoPtr->usage != ACTION_CRYPT )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_ORIGINATOR ) );
				usage = ACTION_CRYPT;
				if( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_ORIGINATOR ) );
				break;

			case CRYPT_ENVINFO_KEYSET_ENCRYPT:
				checkType = MESSAGE_CHECK_PKC_ENCRYPT;
				if( envelopeInfoPtr->iEncryptionKeyset != CRYPT_ERROR )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_KEYSET_ENCRYPT ) );
				break;

			case CRYPT_ENVINFO_KEYSET_DECRYPT:
				checkType = MESSAGE_CHECK_PKC_DECRYPT;
				if( envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_KEYSET_DECRYPT ) );
				break;

			case CRYPT_ENVINFO_KEYSET_SIGCHECK:
				checkType = MESSAGE_CHECK_PKC_SIGCHECK;
				if( envelopeInfoPtr->iSigCheckKeyset != CRYPT_ERROR )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_KEYSET_SIGCHECK ) );
				break;

			default:
				assert( NOTREACHED );
			}
	if( checkType != MESSAGE_CHECK_NONE )
		{
		/* Check the object as appropriate.  A key agreement key can also act
		   as a public key because of the way KEA works, so if a check for a
		   straight public key fails we try again to see if it's a key
		   agreement key with import capabilities */
		status = krnlSendMessage( value, IMESSAGE_CHECK, NULL, checkType );
		if( status == CRYPT_ARGERROR_OBJECT && \
			messageValue == CRYPT_ENVINFO_PUBLICKEY )
			status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									  MESSAGE_CHECK_PKC_KA_IMPORT );
		if( cryptStatusError( status ) )
			return( CRYPT_ARGERROR_NUM1 );

		/* Make sure that the object corresponds to a representable algorithm
		   type.  Note that this check isn't totally foolproof on de-
		   enveloping PGP data since the user can push the hash context 
		   before they push the signed data (to signifiy the use of a 
		   detached signature) so that it's checked using the default 
		   (CMS) algorithm values rather then PGP ones */
		if( checkType == MESSAGE_CHECK_CRYPT || \
			checkType == MESSAGE_CHECK_HASH || \
			checkType == MESSAGE_CHECK_MAC )
			{
			CRYPT_ALGO_TYPE algorithm;

			krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, &algorithm,
							 CRYPT_CTXINFO_ALGO );
			if( checkType == MESSAGE_CHECK_CRYPT )
				{
				CRYPT_MODE_TYPE mode;

				krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, &mode,
								 CRYPT_CTXINFO_MODE );
				status = envelopeInfoPtr->checkCryptAlgo( algorithm, mode );
				}
			else
				status = envelopeInfoPtr->checkHashAlgo( algorithm );
			if( cryptStatusError( status ) )
				return( CRYPT_ERROR_NOTAVAIL );
			}

		/* If we're using CMS enveloping, the object must have an initialised 
		   cert of the correct type associated with it.  Most of this will be 
		   caught by the kernel, but there are a couple of special cases (eg 
		   attribute cert where the main object is a PKC context) which are 
		   missed by the general kernel checks */
		if( ( messageValue == CRYPT_ENVINFO_SIGNATURE || \
			  messageValue == CRYPT_ENVINFO_PUBLICKEY || \
			  messageValue == CRYPT_ENVINFO_PRIVATEKEY || \
			  messageValue == CRYPT_ENVINFO_ORIGINATOR ) && 
			( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
			  envelopeInfoPtr->type == CRYPT_FORMAT_SMIME ) )
			{
			int inited, certType;

			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, &inited, 
									  CRYPT_CERTINFO_IMMUTABLE );
			if( cryptStatusError( status ) || !inited )
				return( CRYPT_ARGERROR_NUM1 );
			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
									  &certType, CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) ||
				( certType != CRYPT_CERTTYPE_CERTIFICATE && \
				  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
				return( CRYPT_ARGERROR_NUM1 );
			}
		}

	/* Add it to the envelope */
	status = envelopeInfoPtr->addInfo( envelopeInfoPtr, messageValue,
									   &value, 0 );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_INITED )
			return( exitErrorInited( envelopeInfoPtr, messageValue ) );
		return( status );
		}
	if( usage != ACTION_NONE )
		/* The action was successfully added, update the usage if 
		   necessary */
		envelopeInfoPtr->usage = usage;
	return( CRYPT_OK );
	}

static int processSetAttributeS( ENVELOPE_INFO *envelopeInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	ACTION_TYPE usage = ACTION_NONE;
	int status;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_ENVINFO_PASSWORD:
			/* Set the envelope usage type based on the fact that we've been
			   fed a password */
			if( envelopeInfoPtr->usage == ACTION_NONE )
				usage = ACTION_CRYPT;
			else		
				if( envelopeInfoPtr->usage != ACTION_CRYPT && \
					envelopeInfoPtr->usage != ACTION_MAC )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_PASSWORD ) );

			/* In general we can't add new enveloping information once we've
			   started processing data */
			if( envelopeInfoPtr->state != STATE_PREDATA && \
				!( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) )
				/* We can't add new information once we've started enveloping */
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_PASSWORD ) );

			/* Add it to the envelope */
			status = envelopeInfoPtr->addInfo( envelopeInfoPtr,
						CRYPT_ENVINFO_PASSWORD, msgData->data, msgData->length );
			break;

		case CRYPT_ENVINFO_RECIPIENT:
			{
			MESSAGE_KEYMGMT_INFO getkeyInfo;

			/* Set the envelope usage type based on the fact that we've been
			   fed a recipient email address */
			if( envelopeInfoPtr->usage != ACTION_NONE && \
				envelopeInfoPtr->usage != ACTION_CRYPT )
				return( CRYPT_ARGERROR_VALUE );
			usage = ACTION_CRYPT;

			/* Make sure that there's a keyset available to pull the 
			   recipient's key from */
			if( envelopeInfoPtr->iEncryptionKeyset == CRYPT_ERROR )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_ENVINFO_KEYSET_ENCRYPT ) );

			/* Try and read the recipient's key from the keyset.  Some 
			   keysets (particularly PKCS #11 devices, for which apps set 
			   the usage flags more or less at random) may not be able to 
			   differentiate between encryption and signature keys based on 
			   the information they have.  This isn't a problem when matching 
			   a key based on a unique ID, but with the use of the recipient 
			   name as the ID there could be multiple possible matches.  
			   Before we try and use the key we therefore perform an extra 
			   check here to make sure that it really is an encryption-
			   capable key */
			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_KEYID_EMAIL, 
								   msgData->data, msgData->length, NULL, 0, 
								   KEYMGMT_FLAG_USAGE_CRYPT );
			status = krnlSendMessage( envelopeInfoPtr->iEncryptionKeyset,
									  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
									  KEYMGMT_ITEM_PUBLICKEY );
			if( cryptStatusOK( status ) && \
				cryptStatusError( \
					krnlSendMessage( getkeyInfo.cryptHandle, IMESSAGE_CHECK, 
									 NULL, MESSAGE_CHECK_PKC_ENCRYPT ) ) )
				{
				krnlSendNotifier( getkeyInfo.cryptHandle,
								  IMESSAGE_DECREFCOUNT );
				status = CRYPT_ERROR_NOTFOUND;
				}
			if( cryptStatusOK( status ) )
				{
				/* We got the key, add it to the envelope */
				status = envelopeInfoPtr->addInfo( envelopeInfoPtr,
												   CRYPT_ENVINFO_PUBLICKEY,
												   &getkeyInfo.cryptHandle, 0 );
				krnlSendNotifier( getkeyInfo.cryptHandle,
								  IMESSAGE_DECREFCOUNT );
				}
			break;
			}

		default:
			assert( NOTREACHED );
		}

	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_INITED )
			return( exitErrorInited( envelopeInfoPtr, messageValue ) );
		return( status );
		}
	if( usage != ACTION_NONE )
		/* The action was successfully added, update the usage if 
		   necessary */
		envelopeInfoPtr->usage = usage;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Envelope Data Handling Functions				*
*																			*
****************************************************************************/

/* Push data into an envelope */

static int envelopePush( ENVELOPE_INFO *envelopeInfoPtr, void *buffer,
						 const int length, int *bytesCopied )
	{
	int status;

	/* Clear return value */
	*bytesCopied = 0;

	/* If we haven't started processing data yet, handle the initial data
	   specially */
	if( envelopeInfoPtr->state == STATE_PREDATA )
		{
		CRYPT_ATTRIBUTE_TYPE missingInfo;

		/* Make sure that all the information we need to proceed is 
		   present */
		assert( envelopeInfoPtr->checkMissingInfo != NULL );
		missingInfo = envelopeInfoPtr->checkMissingInfo( envelopeInfoPtr );
		if( missingInfo != CRYPT_ATTRIBUTE_NONE )
			return( exitErrorNotInited( envelopeInfoPtr, missingInfo ) );

		/* If the envelope buffer hasn't been allocated yet, allocate it now */
		if( envelopeInfoPtr->buffer == NULL )
			{
			if( ( envelopeInfoPtr->buffer = \
							clAlloc( "envelopePush", \
									 envelopeInfoPtr->bufSize ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			memset( envelopeInfoPtr->buffer, 0, envelopeInfoPtr->bufSize );
			}

		/* Emit the header information into the envelope */
		status = envelopeInfoPtr->processPreambleFunction( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			if( !isRecoverableError( status ) )
				envelopeInfoPtr->errorState = status;
			return( status );
			}

		/* The envelope is ready to process data, move it into the high
		   state */
		krnlSendMessage( envelopeInfoPtr->objectHandle, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );
		envelopeInfoPtr->state = STATE_DATA;
		}

	/* If we're in the main data processing state, add the data and perform
	   any necessary actions on it */
	if( envelopeInfoPtr->state == STATE_DATA )
		{
		if( length )
			{
			/* Copy the data to the envelope */
			status = envelopeInfoPtr->copyToEnvelopeFunction( envelopeInfoPtr,
															  buffer, length );
			if( cryptStatusError( status ) )
				{
				if( !isRecoverableError( status ) )
					envelopeInfoPtr->errorState = status;
				return( status );
				}
			*bytesCopied = status;

			return( ( *bytesCopied < length ) ? \
					CRYPT_ERROR_OVERFLOW : CRYPT_OK );
			}

		/* This was a flush, move on to the postdata state */
		envelopeInfoPtr->state = STATE_POSTDATA;
		envelopeInfoPtr->envState = ENVSTATE_NONE;
		}

	assert( envelopeInfoPtr->state == STATE_POSTDATA );

	/* We're past the main data-processing state, emit the postamble */
	status = envelopeInfoPtr->processPostambleFunction( envelopeInfoPtr );
	if( cryptStatusError( status ) )
		{
		if( !isRecoverableError( status ) )
			envelopeInfoPtr->errorState = status;
		return( status );
		}
	envelopeInfoPtr->state = STATE_FINISHED;

	return( CRYPT_OK );
	}

static int deenvelopePush( ENVELOPE_INFO *envelopeInfoPtr, void *buffer,
						   const int length, int *bytesCopied )
	{
	BYTE *bufPtr = ( BYTE * ) buffer;
	int bytesIn = length, status = CRYPT_OK;

	/* Clear return value */
	*bytesCopied = 0;

	/* If we haven't started processing data yet, handle the initial data
	   specially */
	if( envelopeInfoPtr->state == STATE_PREDATA )
		{
		/* Perform any initialisation actions */
		if( envelopeInfoPtr->buffer == NULL )
			{
			/* Allocate the envelope buffer */
			if( ( envelopeInfoPtr->buffer = \
							clAlloc( "deenvelopePush", \
									 envelopeInfoPtr->bufSize ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			memset( envelopeInfoPtr->buffer, 0, envelopeInfoPtr->bufSize );

#ifdef USE_PGP
			/* Try and determine what the data format being used is.  If it 
			   looks like PGP data, try and process it as such, otherwise 
			   default to PKCS #7/CMS/S/MIME */
			if( length && ( bufPtr[ 0 ] & 0x80 ) )
				{
				/* When we initially created the envelope we defaulted to CMS
				   formatting, so we first switch to PGP enveloping to 
				   override the CMS default and then finally select PGP de-
				   enveloping */
				envelopeInfoPtr->type = CRYPT_FORMAT_PGP;
				initPGPEnveloping( envelopeInfoPtr );
				initPGPDeenveloping( envelopeInfoPtr );
				}
#endif /* USE_PGP */
			}

		/* Since we're processing out-of-band information, just copy it in
		   directly */
		if( bytesIn )
			{
			int bytesToCopy = min( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos,
								   bytesIn );
			if( bytesToCopy )
				{
				memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
						bufPtr, bytesToCopy );
				envelopeInfoPtr->bufPos += bytesToCopy;
				bytesIn -= bytesToCopy;
				*bytesCopied = bytesToCopy;
				bufPtr += bytesToCopy;
				}
			}

		/* Process the preamble */
		status = envelopeInfoPtr->processPreambleFunction( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			if( !isRecoverableError( status ) )
				envelopeInfoPtr->errorState = status;
			return( status );
			}

		/* The envelope is ready to process data, move it into the high
		   state */
		krnlSendMessage( envelopeInfoPtr->objectHandle, IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );

		/* Move on to the data-processing state */
		envelopeInfoPtr->state = STATE_DATA;
		}

	/* If we're in the main data processing state, add the data and perform
	   any necessary actions on it */
	if( envelopeInfoPtr->state == STATE_DATA )
		{
		/* If there's data to be copied, copy it into the envelope.  If we've
		   come from the predata state, we may have zero bytes to copy if
		   everything was consumed by the preamble processing, or there may
		   be room to copy more in now if the preamble processing consumed 
		   some of what was present */
		if( bytesIn )
			{
			/* Copy the data to the envelope */
			const int byteCount = \
				envelopeInfoPtr->copyToEnvelopeFunction( envelopeInfoPtr,
														 bufPtr, bytesIn );
			if( cryptStatusError( byteCount ) )
				{
				if( !isRecoverableError( byteCount ) )
					envelopeInfoPtr->errorState = byteCount;
				return( byteCount );
				}
			*bytesCopied += byteCount;
			bytesIn -= byteCount;
			bufPtr += byteCount;
			}

		/* If we've reached the end of the payload (either by having seen the
		   EOC octets with the indefinite encoding, by having reached the end 
		   of the single segment with the definite encoding, or through an
		   explicit flush for unknown-length data), move on to the postdata 
		   state */
		if( ( envelopeInfoPtr->dataFlags & ENVDATA_ENDOFCONTENTS ) || \
			( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
			  envelopeInfoPtr->segmentSize <= 0 ) || \
			( envelopeInfoPtr->payloadSize == CRYPT_UNUSED && \
			  envelopeInfoPtr->segmentSize == CRYPT_UNUSED && length <= 0 ) )
			{
			envelopeInfoPtr->state = STATE_POSTDATA;
			envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
			}
		}

	/* If we're past the main data-processing state, process the postamble */
	if( envelopeInfoPtr->state == STATE_POSTDATA )
		{
		/* Since we're processing trailer information, just copy it in
		   directly */
		if( bytesIn )
			{
/* The handling of EOC information in all situations is very tricky.  With
   PKCS #5 padded data the contents look like:

		    dataLeft	 bufPos
			v			 v
	[ data ][ pad ][ EOC / EOC ]

   The previous processEOC() would leave bufPos as above, the new version
   moves it down to the same location as dataLeft so that after further
   copying it becomes:

		    dataLeft = bufPos
			v
	[ data ][ EOC ]

   ie it adjusts both dataLeft and bufPos for padding rather than just
   dataLeft.  For the original version of processEOC(), the two code 
   alternatives below produced the following results

	- 230K encrypted data, indefinite: Second alternative
	- 230K signed data, indefinite: First alternative and second alternative
	- Short signed data, n-4 bytes, then 4 bytes: First alternative

   The new version works with all self-tests and also with large data amounts.
   This comment has been retained in case a situation is found where it
   doesn't work - 20/09/99 */
#if 1
			const int bytesToCopy = \
					min( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos,
						 bytesIn );
			if( bytesToCopy )
				{
				memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
						bufPtr, bytesToCopy );
				envelopeInfoPtr->bufPos += bytesToCopy;
				*bytesCopied += bytesToCopy;
				}
#else
			const int bytesToCopy = \
					min( envelopeInfoPtr->bufSize - envelopeInfoPtr->dataLeft,
						 bytesIn );
			if( bytesToCopy )
				{
				memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
						bufPtr, bytesToCopy );
				envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + \
										  bytesToCopy;
				*bytesCopied += bytesToCopy;
				}
#endif /* 1 */
			}

		/* Process the postamble.  During this processing we can encounter
		   two special types of recoverable error, CRYPT_ERROR_UNDERFLOW (we
		   need more data to continue) or OK_SPECIAL (we processed all the
		   data, but there's out-of-band information still to go), if it's
		   one of these we don't treat it as a standard error */
		status = envelopeInfoPtr->processPostambleFunction( envelopeInfoPtr );
		if( cryptStatusError( status ) && status != OK_SPECIAL )
			{
			if( !isRecoverableError( status ) )
				envelopeInfoPtr->errorState = status;
			return( status );
			}

		/* If the routine returns OK_SPECIAL then it's processed enough of
		   the postamble for the caller to continue, but there's more to go
		   so we shouldn't change the overall state yet */
		if( status == OK_SPECIAL )
			status = CRYPT_OK;
		else
			/* We've processed all data, we're done unless it's a detached
			   sig with the data supplied out-of-band */
			envelopeInfoPtr->state = \
					( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) ? \
					STATE_EXTRADATA : STATE_FINISHED;

		/* At this point we always exit since the out-of-band data has to be
		   processed in a separate push */
		return( status );
		}

	/* If there's extra out-of-band data present, process it separately.  
	   This is slightly complicated by the fact that the single envelope is
	   being used to process two independent lots of data, so we have to be 
	   careful to distinguish between handling of the main payload data and 
	   handling of this additional out-of-band data */
	if( envelopeInfoPtr->state == STATE_EXTRADATA )
		{
		/* We pass this point twice, the first time round we check the state 
		   and if it's DEENVSTATE_DONE (set when processing of the main data 
		   was completed) we reset it to DEENVSTATE_NONE and make sure that 
		   it's a flush */
		if( envelopeInfoPtr->deenvState == DEENVSTATE_DONE )
			{
			/* We've finished with the main payload data, reset the state for 
			   the additional out-of-band data.  Normally we exit here since 
			   it's a flush, however if the hash value was supplied 
			   externally (which means hashing was never active, since it was 
			   done by the caller), we drop through to the wrap-up, since 
			   there's no second flush of payload data to be performed and so 
			   the flush applies to both sets of data */
			envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
			if( envelopeInfoPtr->dataFlags & ENVDATA_HASHACTIONSACTIVE )
				return( length ? CRYPT_ERROR_BADDATA : CRYPT_OK );
			}

		/* This is just raw additional data so we feed it directly to the 
		   processing function */
		status = envelopeInfoPtr->processExtraData( envelopeInfoPtr, buffer,
													length );
		if( cryptStatusOK( status ) )
			{
			*bytesCopied = length;
			if( !length )
				envelopeInfoPtr->state = STATE_FINISHED;
			}
		}

	return( status );
	}

/* Pop data from an envelope */

static int envelopePop( ENVELOPE_INFO *envelopeInfoPtr, void *buffer,
						const int length, int *bytesCopied )
	{
	int status;

	/* Copy the data from the envelope to the output */
	status = envelopeInfoPtr->copyFromEnvelopeFunction( envelopeInfoPtr, 
														buffer, length );
	if( cryptStatusError( status ) )
		{
		envelopeInfoPtr->errorState = status;
		return( status );
		}
	*bytesCopied = status;
	return( CRYPT_OK );
	}

static int deenvelopePop( ENVELOPE_INFO *envelopeInfoPtr, void *buffer,
						  const int length, int *bytesCopied )
	{
	int status;

	/* If we haven't reached the data yet force a flush to try and get to the 
	   data.  We can end up with this condition if the caller pushes in 
	   deenveloping information and then immediately tries to pop data 
	   without an intervening flush (or implicit flush on the initial push) to 
	   resolve the state of the data in the envelope */
	if( envelopeInfoPtr->state == STATE_PREDATA )
		{
		int dummy;

		status = deenvelopePush( envelopeInfoPtr, NULL, 0, &dummy );
		if( cryptStatusError( status ) )
			return( status );

		/* If we still haven't got anywhere, return an underflow error */
		if( envelopeInfoPtr->state == STATE_PREDATA )
			return( CRYPT_ERROR_UNDERFLOW );
		}

	/* Copy the data from the envelope to the output */
	status = envelopeInfoPtr->copyFromEnvelopeFunction( envelopeInfoPtr, 
														buffer, length );
	if( cryptStatusError( status ) )
		{
		envelopeInfoPtr->errorState = status;
		return( status );
		}
	*bytesCopied = status;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Envelope Message Handler					*
*																			*
****************************************************************************/

/* Handle a message sent to an envelope */

static int envelopeMessageFunction( const void *objectInfoPtr,
									const MESSAGE_TYPE message,
									void *messageDataPtr,
									const int messageValue )
	{
	ENVELOPE_INFO *envelopeInfoPtr = ( ENVELOPE_INFO * ) objectInfoPtr;

	/* Process destroy object messages */
	if( message == MESSAGE_DESTROY )
		{
		int status = CRYPT_OK;

		/* Check to see whether the envelope still needs operations performed
		   on it to resolve the state of the data within it (for example if
		   the caller pushes data but doesn't flush it, there will be a few
		   bytes left that can't be popped).  For enveloping, destroying the 
		   envelope while it's in any state other than STATE_PREDATA or 
		   STATE_FINISHED is regarded as an error.  For de-enveloping we have 
		   to be more careful, since deenveloping information required to 
		   resolve the envelope state could be unavailable, so we shouldn't 
		   return an error if something like a signature check remains to be 
		   done.  What we therefore do is check to see whether we've processed 
		   any data yet and report an error if there's any data left in the 
		   envelope or if we destroy it in the middle of processing data */
		if( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE )
			{
			/* If we've got to the point of processing data in the envelope
			   and there's either more to come or some left to pop, we
			   shouldn't be destroying it yet */
			if( envelopeInfoPtr->state == STATE_DATA || \
				( ( envelopeInfoPtr->state == STATE_POSTDATA || \
					envelopeInfoPtr->state == STATE_FINISHED ) && \
				  envelopeInfoPtr->dataLeft > 0 ) )
				status = CRYPT_ERROR_INCOMPLETE;
			}
		else
			/* If we're in the middle of processing data, we shouldn't be
			   destroying the envelope yet */
			if( envelopeInfoPtr->state != STATE_PREDATA && \
				envelopeInfoPtr->state != STATE_FINISHED )
				status = CRYPT_ERROR_INCOMPLETE;

		/* Delete the action and content lists */
		deleteActionList( envelopeInfoPtr->memPoolState, 
						  envelopeInfoPtr->preActionList );
		deleteActionList( envelopeInfoPtr->memPoolState, 
						  envelopeInfoPtr->actionList );
		deleteActionList( envelopeInfoPtr->memPoolState, 
						  envelopeInfoPtr->postActionList );
		deleteContentList( envelopeInfoPtr->memPoolState, 
						   envelopeInfoPtr->contentList );

#ifdef USE_COMPRESSION
		/* Delete the zlib compression state information if necessary */
		if( envelopeInfoPtr->flags & ENVELOPE_ZSTREAMINITED )
			{
			if( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE )
				inflateEnd( &envelopeInfoPtr->zStream );
			else
				deflateEnd( &envelopeInfoPtr->zStream );
			}
#endif /* USE_COMPRESSION */

		/* Clean up keysets */
		if( envelopeInfoPtr->iSigCheckKeyset != CRYPT_ERROR )
			krnlSendNotifier( envelopeInfoPtr->iSigCheckKeyset,
							  IMESSAGE_DECREFCOUNT );
		if( envelopeInfoPtr->iEncryptionKeyset != CRYPT_ERROR )
			krnlSendNotifier( envelopeInfoPtr->iEncryptionKeyset,
							  IMESSAGE_DECREFCOUNT );
		if( envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR )
			krnlSendNotifier( envelopeInfoPtr->iDecryptionKeyset,
							  IMESSAGE_DECREFCOUNT );

		/* Clean up other envelope objects */
		if( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR )
			krnlSendNotifier( envelopeInfoPtr->iExtraCertChain,
							  IMESSAGE_DECREFCOUNT );

		/* Clear and free the buffers if necessary */
		if( envelopeInfoPtr->buffer != NULL )
			{
			zeroise( envelopeInfoPtr->buffer, envelopeInfoPtr->bufSize );
			clFree( "envelopeMessageFunction", envelopeInfoPtr->buffer );
			}
		if( envelopeInfoPtr->auxBuffer != NULL )
			{
			zeroise( envelopeInfoPtr->auxBuffer, envelopeInfoPtr->auxBufSize );
			clFree( "envelopeMessageFunction", envelopeInfoPtr->auxBuffer );
			}

		/* Delete the object itself */
		zeroise( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) );
		clFree( "envelopeMessageFunction", envelopeInfoPtr );

		return( status );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		assert( message == MESSAGE_GETATTRIBUTE || \
				message == MESSAGE_GETATTRIBUTE_S || \
				message == MESSAGE_SETATTRIBUTE || \
				message == MESSAGE_SETATTRIBUTE_S );

		if( message == MESSAGE_GETATTRIBUTE )
			return( processGetAttribute( envelopeInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE_S )
			return( processGetAttributeS( envelopeInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE )
			return( processSetAttribute( envelopeInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE_S )
			return( processSetAttributeS( envelopeInfoPtr, messageDataPtr,
										  messageValue ) );

		assert( NOTREACHED );
		return( CRYPT_ERROR );	/* Get rid of compiler warn */
		}

	/* Process object-specific messages */
	if( message == MESSAGE_ENV_PUSHDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int bytesCopied, status;

		assert( ( msgData->data == NULL && msgData->length == 0 ) || \
				( msgData->data != NULL && msgData->length > 0 ) );

		/* Make sure that everything is in order */
		if( msgData->length == 0 )
			{
			/* If it's a flush, make sure that we're in a state where this is
			   valid.  We can only perform a flush on enveloping if we're in
			   the data or postdata state, on deenveloping a flush can
			   happen at any time since the entire payload could be buffered
			   pending the addition of a deenveloping resource, so the
			   envelope goes from pre -> post in one step.  There is however
			   one special case in which a push in the pre-data state is 
			   valid and that's when we're creating a zero-length CMS signed 
			   message as a means of communicating authenticated attributes 
			   (of all the standard users of CMS, only SCEP normally does 
			   this).  In order to indicate that this special case is in
			   effect, we require that the user set the ENVELOPE_ATTRONLY
			   flag before pushing data, although for completeness we could 
			   also check the CMS attributes for the presence of SCEP 
			   attributes.  The downside of this additional checking is that 
			   it makes any non-SCEP use of signature-only CMS envelopes 
			   impossible */
			if( envelopeInfoPtr->state == STATE_FINISHED )
				return( CRYPT_OK );
			if( !( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) && \
				( envelopeInfoPtr->state != STATE_DATA && \
				  envelopeInfoPtr->state != STATE_POSTDATA ) && \
				!( envelopeInfoPtr->state == STATE_PREDATA && \
				   envelopeInfoPtr->usage == ACTION_SIGN && \
				   envelopeInfoPtr->type == CRYPT_FORMAT_CMS && \
				   ( envelopeInfoPtr->flags & ENVELOPE_ATTRONLY ) ) )
				return( CRYPT_ERROR_INCOMPLETE );
			}
		else
			if( envelopeInfoPtr->state == STATE_FINISHED )
				return( CRYPT_ERROR_COMPLETE );
		if( envelopeInfoPtr->errorState != CRYPT_OK )
			return( envelopeInfoPtr->errorState );
		if( !( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) && \
			( envelopeInfoPtr->dataFlags & ENVDATA_NOSEGMENT ) && \
			envelopeInfoPtr->payloadSize == CRYPT_UNUSED )
			/* If we're enveloping using a non-segmenting encoding of the 
			   payload, the caller has to explicitly set the payload size 
			   before they can add any data */
			return( exitErrorNotInited( envelopeInfoPtr, 
										CRYPT_ENVINFO_DATASIZE ) );

		/* Send the data to the envelope */
		if( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE )
			status = deenvelopePush( envelopeInfoPtr, msgData->data,
									 msgData->length, &bytesCopied );
		else
			status = envelopePush( envelopeInfoPtr, msgData->data,
								   msgData->length, &bytesCopied );
		msgData->length = bytesCopied;
		return( status );
		}
	if( message == MESSAGE_ENV_POPDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int bytesCopied, status;

		assert( msgData->data != NULL && msgData->length > 0 );

		/* Make sure that everything is in order */
		if( envelopeInfoPtr->errorState != CRYPT_OK )
			return( envelopeInfoPtr->errorState );

		/* Get the data from the envelope */
		if( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE )
			status = deenvelopePop( envelopeInfoPtr, msgData->data,
									msgData->length, &bytesCopied );
		else
			status = envelopePop( envelopeInfoPtr, msgData->data,
								  msgData->length, &bytesCopied );
		msgData->length = bytesCopied;
		return( status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warn */
	}

/* Create an envelope.  This is a low-level function encapsulated by
   createEnvelope() and used to manage error exits */

static int initEnvelope( CRYPT_ENVELOPE *iCryptEnvelope,
						 const CRYPT_USER cryptOwner,
						 const CRYPT_FORMAT_TYPE formatType,
						 ENVELOPE_INFO **envelopeInfoPtrPtr )
	{
	ENVELOPE_INFO *envelopeInfoPtr;
	const BOOLEAN isDeenvelope = ( formatType == CRYPT_FORMAT_AUTO ) ? \
								 TRUE : FALSE;
	const int subType = \
			isDeenvelope ? SUBTYPE_ENV_DEENV : \
			( formatType == CRYPT_FORMAT_PGP ) ? \
				SUBTYPE_ENV_ENV_PGP : SUBTYPE_ENV_ENV;
	const int storageSize = 3 * sizeof( CONTENT_LIST );
	int status;

	/* Clear the return values */
	*iCryptEnvelope = CRYPT_ERROR;
	*envelopeInfoPtrPtr = NULL;

	/* If PGP support is disabled, we can't specify PGP as a target format */
#ifndef USE_PGP
	if( formatType == CRYPT_FORMAT_PGP )
		return( CRYPT_ARGERROR_NUM1 );
#endif /* USE_PGP */

	/* Create the envelope object */
	status = krnlCreateObject( ( void ** ) &envelopeInfoPtr, 
							   sizeof( ENVELOPE_INFO ) + storageSize, 
							   OBJECT_TYPE_ENVELOPE, subType, 
							   CREATEOBJECT_FLAG_NONE, cryptOwner, 
							   ACTION_PERM_NONE_ALL, envelopeMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*envelopeInfoPtrPtr = envelopeInfoPtr;
	*iCryptEnvelope = envelopeInfoPtr->objectHandle = status;
	envelopeInfoPtr->ownerHandle = cryptOwner;
	envelopeInfoPtr->bufSize = DEFAULT_BUFFER_SIZE;
	if( isDeenvelope )
		envelopeInfoPtr->flags = ENVELOPE_ISDEENVELOPE;
	envelopeInfoPtr->type = formatType;
	envelopeInfoPtr->state = STATE_PREDATA;
	envelopeInfoPtr->storageSize = storageSize;
	initMemPool( envelopeInfoPtr->memPoolState, envelopeInfoPtr->storage, 
				 storageSize );

	/* Set up any internal objects to contain invalid handles */
	envelopeInfoPtr->iCryptContext = \
		envelopeInfoPtr->iExtraCertChain = CRYPT_ERROR;
	envelopeInfoPtr->iSigCheckKeyset = envelopeInfoPtr->iEncryptionKeyset = \
		envelopeInfoPtr->iDecryptionKeyset = CRYPT_ERROR;
	envelopeInfoPtr->payloadSize = CRYPT_UNUSED;

	/* Set up the enveloping methods */
	if( formatType == CRYPT_FORMAT_PGP )
		initPGPEnveloping( envelopeInfoPtr );
	else
		initCMSEnveloping( envelopeInfoPtr );
	if( isDeenvelope )
		initDeenvelopeStreaming( envelopeInfoPtr );
	else
		initEnvelopeStreaming( envelopeInfoPtr );
	initResourceHandling( envelopeInfoPtr );

	/* Set up the de-enveloping methods.  We default to PKCS #7/CMS/SMIME, 
	   if the data is in some other format we'll adjust the function 
	   pointers once the user pushes in the first data quantity */
	if( isDeenvelope )
		initCMSDeenveloping( envelopeInfoPtr );

	return( CRYPT_OK );
	}

int createEnvelope( MESSAGE_CREATEOBJECT_INFO *createInfo, 
					const void *auxDataPtr, const int auxValue )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	ENVELOPE_INFO *envelopeInfoPtr;
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( createInfo->arg1 <= CRYPT_FORMAT_NONE || \
		createInfo->arg1 >= CRYPT_FORMAT_LAST_EXTERNAL )
		return( CRYPT_ARGERROR_NUM1 );

	/* Pass the call on to the lower-level open function */
	initStatus = initEnvelope( &iCryptEnvelope, createInfo->cryptOwner,
							   createInfo->arg1, &envelopeInfoPtr );
	if( envelopeInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The init failed, make sure that the object gets destroyed when we 
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptEnvelope, IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel the object is ready for use */
	status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptEnvelope;
	return( CRYPT_OK );
	}
#endif /* USE_ENVELOPES */
