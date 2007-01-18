/****************************************************************************
*																			*
*							Key Exchange Routines							*
*						Copyright Peter Gutmann 1993-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "mech.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "mechs/mech.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Import a Session Key						*
*																			*
****************************************************************************/

/* Try and determine the format of the encrypted data */

static CRYPT_FORMAT_TYPE getFormatType( const void *data, 
										const int dataLength )
	{
	CRYPT_FORMAT_TYPE formatType = CRYPT_FORMAT_NONE;
	STREAM stream;
	const int dataReadLength = min( dataLength, 16 );
	long value;
	int status;

	assert( isReadPtr( data, MIN_CRYPT_OBJECTSIZE ) );
	assert( dataLength >= MIN_CRYPT_OBJECTSIZE );

	sMemConnect( &stream, data, dataReadLength );

	/* Figure out what we've got.  PKCS #7/CMS/SMIME keyTrans begins:

		keyTransRecipientInfo ::= SEQUENCE {
			version		INTEGER (0|2),

	   while a kek begins:

		kekRecipientInfo ::= [3] IMPLICIT SEQUENCE {
			version		INTEGER (0),

	   which allows us to determine which type of object we have */
	if( sPeek( &stream ) == BER_SEQUENCE )
		{
		readSequence( &stream, NULL );
		status = readShortInteger( &stream, &value );
		if( cryptStatusOK( status ) )
			{
			switch( value )
				{
				case KEYTRANS_VERSION:
					formatType = CRYPT_FORMAT_CMS;
					break;

				case KEYTRANS_EX_VERSION:
					formatType = CRYPT_FORMAT_CRYPTLIB;
					break;

				default:
					formatType = CRYPT_FORMAT_NONE;
				}
			}
		sMemDisconnect( &stream );

		return( formatType );
		}
	if( sPeek( &stream ) == MAKE_CTAG( 3 ) )
		{
		readConstructed( &stream, NULL, 3 );
		status = readShortInteger( &stream, &value );
		if( cryptStatusOK( status ) )
			formatType = ( value == PWRI_VERSION ) ? \
						 CRYPT_FORMAT_CRYPTLIB : CRYPT_FORMAT_NONE;
		sMemDisconnect( &stream );

		return( formatType );
		}

#ifdef USE_PGP
	/* It's not ASN.1 data, check for PGP data */
	status = pgpReadPacketHeader( &stream, NULL, &value, 30 );
	if( cryptStatusOK( status ) && value > 30 && value < 8192 )
		{
		sMemDisconnect( &stream );
		return( CRYPT_FORMAT_PGP );
		}
#endif /* USE_PGP */

	sMemDisconnect( &stream );

	return( CRYPT_FORMAT_NONE );
	}

/* Check that the context data is encodable using the chosen format */

static int checkContextsEncodable( const CRYPT_HANDLE exportKey,
								   const CRYPT_ALGO_TYPE exportAlgo,
								   const CRYPT_CONTEXT sessionKeyContext,
								   const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ALGO_TYPE sessionKeyAlgo;
	CRYPT_MODE_TYPE sessionKeyMode, exportMode;
	const BOOLEAN exportIsPKC = ( exportAlgo >= CRYPT_ALGO_FIRST_PKC && \
								  exportAlgo <= CRYPT_ALGO_LAST_PKC ) ? \
								TRUE : FALSE;
	BOOLEAN sessionIsMAC = FALSE;
	int status;

	assert( isHandleRangeValid( exportKey ) );
	assert( exportAlgo > CRYPT_ALGO_NONE && exportAlgo < CRYPT_ALGO_LAST );
	assert( isHandleRangeValid( sessionKeyContext ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST_EXTERNAL );

	/* Get any required context information */
	status = krnlSendMessage( sessionKeyContext, MESSAGE_GETATTRIBUTE,
							  &sessionKeyAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM3 );
	if( sessionKeyAlgo >= CRYPT_ALGO_FIRST_MAC && \
		sessionKeyAlgo <= CRYPT_ALGO_LAST_MAC )
		sessionIsMAC = TRUE;
	else
		{
		status = krnlSendMessage( sessionKeyContext, MESSAGE_GETATTRIBUTE,
								  &sessionKeyMode, CRYPT_CTXINFO_MODE );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_PARAM3 );
		}

	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			/* Check that the export algorithm is encodable */
			if( exportIsPKC )
				{
				if( cryptStatusError( sizeofAlgoID( exportAlgo ) ) )
					return( CRYPT_ERROR_PARAM1 );
				}
			else
				{
				/* If it's a conventional key export, the key wrap mechanism 
				   requires the use of CBC mode for the wrapping */
				status = krnlSendMessage( exportKey, MESSAGE_GETATTRIBUTE, 
										  &exportMode, CRYPT_CTXINFO_MODE );
				if( cryptStatusError( status ) )
					return( CRYPT_ERROR_PARAM1 );
				if( exportMode != CRYPT_MODE_CBC || \
					cryptStatusError( sizeofAlgoIDex( exportAlgo, \
													  exportMode, 0 ) ) )
					return( CRYPT_ERROR_PARAM1 );
				}

			/* Check that the session-key algorithm is encodable */
			if( sessionIsMAC )
				status = sizeofAlgoID( sessionKeyAlgo );
			else
				status = checkAlgoID( sessionKeyAlgo, sessionKeyMode );
			if( cryptStatusError( status ) )
				return( CRYPT_ERROR_PARAM3 );

			return( CRYPT_OK );

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			/* Check that the export algorithm is encodable */
			if( cryptlibToPgpAlgo( exportAlgo ) == PGP_ALGO_NONE )
				return( CRYPT_ERROR_PARAM1 );

			/* Check that the session-key algorithm is encodable */
			if( exportIsPKC )
				{
				if( cryptlibToPgpAlgo( sessionKeyAlgo ) == PGP_ALGO_NONE )
					return( CRYPT_ERROR_PARAM3 );
				if( sessionKeyMode != CRYPT_MODE_CFB )
					return( CRYPT_ERROR_PARAM3 );
				}
			else
				{
				/* If it's a conventional key export, there's no key wrap as 
				   in CMS (the session-key context isn't used), so the 
				   "export context" mode must be CFB */
				status = krnlSendMessage( exportKey, MESSAGE_GETATTRIBUTE, 
										  &exportMode, CRYPT_CTXINFO_MODE );
				if( cryptStatusError( status ) )
					return( CRYPT_ERROR_PARAM1 );
				if( exportMode != CRYPT_MODE_CFB )
					return( CRYPT_ERROR_PARAM1 );
				}

			return( CRYPT_OK );
#endif /* USE_PGP */
		}
	
	/* It's an invalid/unknown format, we can't check the encodability of 
	   the context data */
	return( CRYPT_ERROR_PARAM4 );
	}

/* Import an extended encrypted key, either a cryptlib key or a CMS key */

C_RET cryptImportKeyEx( C_IN void C_PTR encryptedKey,
						C_IN int encryptedKeyLength,
						C_IN CRYPT_CONTEXT importKey,
						C_IN CRYPT_CONTEXT sessionKeyContext,
						C_OUT CRYPT_CONTEXT C_PTR returnedContext )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_ALGO_TYPE importAlgo;
	CRYPT_CONTEXT iReturnedContext;
	int owner, originalOwner, status;

	/* Perform basic error checking */
	if( encryptedKeyLength < MIN_CRYPT_OBJECTSIZE )
		return( CRYPT_ERROR_PARAM2 );
	if( !isReadPtr( encryptedKey, encryptedKeyLength ) )
		return( CRYPT_ERROR_PARAM1 );
	if( ( formatType = getFormatType( encryptedKey, \
									  encryptedKeyLength ) ) == CRYPT_FORMAT_NONE )
		return( CRYPT_ERROR_BADDATA );

	/* Check the importing key */
	status = krnlSendMessage( importKey, MESSAGE_GETATTRIBUTE,
							  &importAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM3 : status );
	if( importAlgo >= CRYPT_ALGO_FIRST_PKC && importAlgo <= CRYPT_ALGO_LAST_PKC )
		{
		/* The DLP algorithms have specialised data-formatting requirements
		   and can't normally be directly accessed via external messages,
		   and PKC operations in general may be restricted to internal access
		   only if they have certificates that restrict their use associated
		   with them.  However if we're performing a high-level key import 
		   (rather than a low-level raw context operation) this is OK since 
		   they're being used from cryptlib-internal routines.  Doing the 
		   check via an internal message is safe at this point since we've 
		   already checked the context's external accessibility when we got 
		   the algorithm info */
		status = krnlSendMessage( importKey, IMESSAGE_CHECK, NULL,
								  ( importAlgo == CRYPT_ALGO_DH ) ? \
									MESSAGE_CHECK_PKC_KA_IMPORT : \
									MESSAGE_CHECK_PKC_DECRYPT );

		/* If we get a non-inited error with a key agreement key this is OK 
		   since the key parameters are read from the exchanged object */
		if( status == CRYPT_ERROR_NOTINITED && importAlgo == CRYPT_ALGO_DH )
			status = CRYPT_OK;
		}
	else
		status = krnlSendMessage( importKey, MESSAGE_CHECK, NULL,
								  MESSAGE_CHECK_CRYPT );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM3 : status );

	/* Check the session key */
	if( formatType == CRYPT_FORMAT_PGP )
		{
		/* PGP stores the session key information with the encrypted key
		   data, so the user can't provide a context */
		if( sessionKeyContext != CRYPT_UNUSED )
			return( CRYPT_ERROR_PARAM4 );
		if( !isWritePtr( returnedContext, sizeof( CRYPT_CONTEXT ) ) )
			return( CRYPT_ERROR_PARAM5 );
		*returnedContext = CRYPT_ERROR;
		}
	else
		{
		CRYPT_ALGO_TYPE sessionKeyAlgo;

		status = krnlSendMessage( sessionKeyContext, MESSAGE_GETATTRIBUTE,
								  &sessionKeyAlgo, CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( sessionKeyContext, MESSAGE_CHECK, NULL,
							( sessionKeyAlgo >= CRYPT_ALGO_FIRST_MAC ) ? \
								MESSAGE_CHECK_MAC_READY : \
								MESSAGE_CHECK_CRYPT_READY );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
					CRYPT_ERROR_PARAM4 : status );
		if( returnedContext != NULL )
			return( CRYPT_ERROR_PARAM5 );
		}

	/* If the importing key is owned, bind the session key context to the same
	   owner before we load a key into it.  We also need to save the original
	   owner so that we can undo the binding later if things fail */
	status = krnlSendMessage( sessionKeyContext, MESSAGE_GETATTRIBUTE,
							  &originalOwner, CRYPT_PROPERTY_OWNER );
	if( cryptStatusError( status ) )
		originalOwner = CRYPT_ERROR;	/* Non-owned object */
	status = krnlSendMessage( importKey, MESSAGE_GETATTRIBUTE, &owner,
							  CRYPT_PROPERTY_OWNER );
	if( cryptStatusOK( status ) )
		/* Importing key is owned, set the imported key's owner */
		krnlSendMessage( sessionKeyContext, MESSAGE_SETATTRIBUTE, &owner,
						 CRYPT_PROPERTY_OWNER );
	else
		/* Don't try and change the session key ownership */
		originalOwner = CRYPT_ERROR;

	/* Import it as appropriate */
	if( importAlgo >= CRYPT_ALGO_FIRST_PKC && importAlgo <= CRYPT_ALGO_LAST_PKC )
		{
		if( formatType == CRYPT_FORMAT_PGP )
			{
			status = importPublicKey( encryptedKey, encryptedKeyLength,
									  CRYPT_UNUSED, importKey,
									  &iReturnedContext, KEYEX_PGP );
			if( cryptStatusOK( status ) )
				/* Make the newly-created context externally visible */
				krnlSendMessage( iReturnedContext, IMESSAGE_SETATTRIBUTE,
								 MESSAGE_VALUE_FALSE,
								 CRYPT_IATTRIBUTE_INTERNAL );
			}
		else
			status = importPublicKey( encryptedKey, encryptedKeyLength,
									  sessionKeyContext, importKey, NULL,
									  ( formatType == CRYPT_FORMAT_CMS ) ? \
										KEYEX_CMS : KEYEX_CRYPTLIB );
		}
	else
		status = importConventionalKey( encryptedKey, encryptedKeyLength,
							sessionKeyContext, importKey,
							( formatType == CRYPT_FORMAT_CRYPTLIB ) ? \
								KEYEX_CRYPTLIB : KEYEX_PGP );

	/* If the import failed, return the session key context to its
	   original owner */
	if( cryptStatusError( status ) )
		{
		if( originalOwner != CRYPT_ERROR )
			krnlSendMessage( sessionKeyContext, MESSAGE_SETATTRIBUTE,
							 &originalOwner, CRYPT_PROPERTY_OWNER );
		}
	else
		/* If we created the session key as part of the import operation,
		   return it to the caller */
		if( formatType == CRYPT_FORMAT_PGP )
			*returnedContext = iReturnedContext;

	if( cryptArgError( status ) )
		/* If we get an argument error from the lower-level code, map the
		   parameter number to the function argument number */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM4 : CRYPT_ERROR_PARAM3;
	return( status );
	}

C_RET cryptImportKey( C_IN void C_PTR encryptedKey,
					  C_IN int encryptedKeyLength,
					  C_IN CRYPT_CONTEXT importKey,
					  C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	return( cryptImportKeyEx( encryptedKey, encryptedKeyLength, importKey,
							  sessionKeyContext, NULL ) );
	}

/****************************************************************************
*																			*
*								Export a Session Key						*
*																			*
****************************************************************************/

/* Export an extended encrypted key, either a cryptlib key or a CMS key */

C_RET cryptExportKeyEx( C_OUT void C_PTR encryptedKey,
						C_IN int encryptedKeyMaxLength,
						C_OUT int C_PTR encryptedKeyLength,
						C_IN CRYPT_FORMAT_TYPE formatType,
						C_IN CRYPT_HANDLE exportKey,
						C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	CRYPT_ALGO_TYPE exportAlgo, sessionKeyAlgo;
	int status;

	/* Perform basic error checking */
	if( encryptedKey != NULL )
		{
		if( encryptedKeyMaxLength < MIN_CRYPT_OBJECTSIZE )
			return( CRYPT_ERROR_PARAM2 );
		if( !isWritePtr( encryptedKey, encryptedKeyMaxLength ) )
			return( CRYPT_ERROR_PARAM1 );
		memset( encryptedKey, 0, MIN_CRYPT_OBJECTSIZE );
		}
	else
		if( encryptedKeyMaxLength != 0 )
			return( CRYPT_ERROR_PARAM2 );
	if( !isWritePtr( encryptedKeyLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM3 );
	*encryptedKeyLength = 0;
	if( formatType != CRYPT_FORMAT_CRYPTLIB && \
		formatType != CRYPT_FORMAT_CMS && \
		formatType != CRYPT_FORMAT_SMIME && \
		formatType != CRYPT_FORMAT_PGP )
		return( CRYPT_ERROR_PARAM4 );

	/* Check the exporting key */
	status = krnlSendMessage( exportKey, MESSAGE_GETATTRIBUTE, &exportAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM5 : status );
	if( exportAlgo >= CRYPT_ALGO_FIRST_PKC && exportAlgo <= CRYPT_ALGO_LAST_PKC )
		{
		/* The DLP algorithms have specialised data-formatting requirements
		   and can't normally be directly accessed via external messages,
		   and PKC operations in general may be restricted to internal access
		   only if they have certificates that restrict their use associated
		   with them.  However if we're performing a high-level key export 
		   (rather than a low-level raw context operation) this is OK since 
		   they're being used from cryptlib-internal routines.  Doing the 
		   check via an internal message is safe at this point since we've 
		   already checked the context's external accessibility when we got 
		   the algorithm info */
		status = krnlSendMessage( exportKey, IMESSAGE_CHECK, NULL,
								  ( exportAlgo == CRYPT_ALGO_DH ) ? \
									MESSAGE_CHECK_PKC_KA_EXPORT : \
									MESSAGE_CHECK_PKC_ENCRYPT );
		}
	else
		status = krnlSendMessage( exportKey, MESSAGE_CHECK, NULL,
								  MESSAGE_CHECK_CRYPT );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM5 : status );
	status = checkContextsEncodable( exportKey, exportAlgo, 
									 sessionKeyContext, formatType );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ERROR_PARAM1 ) ? CRYPT_ERROR_PARAM5 : \
				( status == CRYPT_ERROR_PARAM3 ) ? CRYPT_ERROR_PARAM6 : \
				CRYPT_ERROR_PARAM4 );

	/* Check the exported key */
	status = krnlSendMessage( sessionKeyContext, MESSAGE_GETATTRIBUTE,
							  &sessionKeyAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM6 );
	status = krnlSendMessage( sessionKeyContext, MESSAGE_CHECK, NULL,
							  ( sessionKeyAlgo >= CRYPT_ALGO_FIRST_MAC && \
								sessionKeyAlgo <= CRYPT_ALGO_LAST_MAC ) ? \
							  MESSAGE_CHECK_MAC : MESSAGE_CHECK_CRYPT );
	if( exportAlgo == CRYPT_ALGO_DH )
		{
		/* If we're using a key agreement algorithm it doesn't matter if the
		   session key context has a key attribute present or not, but the
		   format has to be cryptlib */
		if( status == CRYPT_ERROR_NOTINITED )
			status = CRYPT_OK;
		if( formatType == CRYPT_FORMAT_CMS || \
			formatType == CRYPT_FORMAT_SMIME )
			status = CRYPT_ERROR_PARAM4;
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM6 : status );

	/* Export the key via the shared export function */
	status = iCryptExportKeyEx( encryptedKey, encryptedKeyLength,
								encryptedKeyMaxLength, formatType,
								sessionKeyContext, exportKey );
	if( cryptArgError( status ) )
		/* If we get an argument error from the lower-level code, map the
		   parameter number to the function argument number */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM6 : CRYPT_ERROR_PARAM5;
	return( status );
	}

C_RET cryptExportKey( C_OUT void C_PTR encryptedKey,
					  C_IN int encryptedKeyMaxLength,
					  C_OUT int C_PTR encryptedKeyLength,
					  C_IN CRYPT_HANDLE exportKey,
					  C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	int status;

	status = cryptExportKeyEx( encryptedKey, encryptedKeyMaxLength,
							   encryptedKeyLength, CRYPT_FORMAT_CRYPTLIB,
							   exportKey, sessionKeyContext );
	return( ( status == CRYPT_ERROR_PARAM5 ) ? CRYPT_ERROR_PARAM4 : \
			( status == CRYPT_ERROR_PARAM6 ) ? CRYPT_ERROR_PARAM5 : status );
	}

/****************************************************************************
*																			*
*						Internal Import/Export Functions					*
*																			*
****************************************************************************/

/* Internal versions of the above.  These skip a lot of the checking done by
   the external versions since they're only called by cryptlib internal
   functions that have already checked the parameters for validity */

int iCryptImportKeyEx( const void *encryptedKey, const int encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iImportKey,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   CRYPT_CONTEXT *iReturnedContext )
	{
	CRYPT_ALGO_TYPE importAlgo;
	const KEYEX_TYPE keyexType = \
			( formatType == CRYPT_FORMAT_AUTO || \
			  formatType == CRYPT_FORMAT_CRYPTLIB ) ? KEYEX_CRYPTLIB : \
			( formatType == CRYPT_FORMAT_PGP ) ? KEYEX_PGP : KEYEX_CMS;
	int status;

	assert( isReadPtr( encryptedKey, encryptedKeyLength ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST );
	assert( isHandleRangeValid( iImportKey ) );
	assert( ( formatType == CRYPT_FORMAT_PGP && \
			  iSessionKeyContext == CRYPT_UNUSED ) || \
			( formatType != CRYPT_FORMAT_PGP && \
			  isHandleRangeValid( iSessionKeyContext ) ) );
	assert( ( formatType == CRYPT_FORMAT_PGP && \
			  isWritePtr( iReturnedContext, sizeof( CRYPT_CONTEXT ) ) ) || \
			( formatType != CRYPT_FORMAT_PGP && \
			  iReturnedContext == NULL ) );

	/* Import it as appropriate.  We don't handle key agreement at this
	   level */
	status = krnlSendMessage( iImportKey, IMESSAGE_GETATTRIBUTE, &importAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	if( importAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		importAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		return( importConventionalKey( encryptedKey, encryptedKeyLength,
									   iSessionKeyContext, iImportKey,
									   keyexType ) );
	return( importPublicKey( encryptedKey, encryptedKeyLength,
							 iSessionKeyContext, iImportKey,
							 iReturnedContext, keyexType ) );
	}

int iCryptExportKeyEx( void *encryptedKey, int *encryptedKeyLength,
					   const int encryptedKeyMaxLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iExportKey )
	{
	CRYPT_ALGO_TYPE exportAlgo;
	const KEYEX_TYPE keyexType = \
			( formatType == CRYPT_FORMAT_CRYPTLIB ) ? KEYEX_CRYPTLIB : \
			( formatType == CRYPT_FORMAT_PGP ) ? KEYEX_PGP : KEYEX_CMS;
	DYNBUF auxDB;
	const int encKeyMaxLength = ( encryptedKey == NULL ) ? \
								0 : encryptedKeyMaxLength;
	int status;

	assert( ( encryptedKey == NULL && encryptedKeyMaxLength == 0 ) || \
			( encryptedKeyMaxLength >= MIN_CRYPT_OBJECTSIZE && \
			  isWritePtr( encryptedKey, encryptedKeyMaxLength ) ) );
	assert( isWritePtr( encryptedKeyLength, sizeof( int ) ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST );
	assert( ( formatType == CRYPT_FORMAT_PGP ) || \
			isHandleRangeValid( iSessionKeyContext ) );
	assert( isHandleRangeValid( iExportKey ) );

	/* Clear return value */
	*encryptedKeyLength = 0;

	/* Perform simplified error checking */
	status = krnlSendMessage( iExportKey, IMESSAGE_GETATTRIBUTE, &exportAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );

	/* If it's a non-PKC export, pass the call down to the low-level export
	   function */
	if( exportAlgo < CRYPT_ALGO_FIRST_PKC || exportAlgo > CRYPT_ALGO_LAST_PKC )
		return( exportConventionalKey( encryptedKey, encryptedKeyLength,
									   encKeyMaxLength, iSessionKeyContext, 
									   iExportKey, keyexType ) );

	/* If it's a non-CMS/SMIME PKC export, pass the call down to the low-
	   level export function */
	assert( isHandleRangeValid( iSessionKeyContext ) );
	if( formatType != CRYPT_FORMAT_CMS && formatType != CRYPT_FORMAT_SMIME )
		return( exportPublicKey( encryptedKey, encryptedKeyLength,
								 encKeyMaxLength, iSessionKeyContext, 
								 iExportKey, NULL, 0, keyexType ) );

	/* We're exporting a key in CMS format, we need to obtain recipient 
	   information as auxiliary data for the signature.  First, we lock the 
	   cert for our exclusive use, and in case it's a cert chain, select the 
	   first cert in the chain */
	status = krnlSendMessage( iExportKey, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_PARAM5 );
	krnlSendMessage( iExportKey, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_CURSORFIRST, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );

	/* Next, we get the recipient information from the cert into the 
	   dynbuf */
	status = dynCreate( &auxDB, iExportKey,
						( exportAlgo == CRYPT_ALGO_DH || \
						  exportAlgo == CRYPT_ALGO_KEA ) ? \
							CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER : \
							CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( status ) )
		{
		krnlSendMessage( iExportKey, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
		return( CRYPT_ERROR_PARAM5 );
		}

	/* Finally, we're ready to export the key, alongside the key ID as 
	   auxiliary data */
	status = exportPublicKey( encryptedKey, encryptedKeyLength,
							  encKeyMaxLength, iSessionKeyContext, 
							  iExportKey, dynData( auxDB ), 
							  dynLength( auxDB ), keyexType );

	/* Clean up */
	krnlSendMessage( iExportKey, IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_FALSE, 
					 CRYPT_IATTRIBUTE_LOCKED );
	dynDestroy( &auxDB );

	return( status );
	}
