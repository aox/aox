/****************************************************************************
*																			*
*							cryptlib Keyset Routines						*
*						Copyright Peter Gutmann 1995-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "keyset.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "keyset/keyset.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_KEYSETS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

static int exitError( KEYSET_INFO *keysetInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  const CRYPT_ERRTYPE_TYPE errorType, const int status )
	{
	setErrorInfo( keysetInfoPtr, errorLocus, errorType );
	return( status );
	}

static int exitErrorNotFound( KEYSET_INFO *keysetInfoPtr,
							  const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( keysetInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTFOUND ) );
	}

static int exitErrorIncomplete( KEYSET_INFO *keysetInfoPtr,
								const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( keysetInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT,
					   CRYPT_ERROR_INCOMPLETE ) );
	}

/* Exit after saving a detailed error message.  This is used by lower-level 
   keyset code to provide more information to the caller than a basic error 
   code */

int retExtFnKeyset( KEYSET_INFO *keysetInfoPtr, const int status, 
					const char *format, ... )
	{
	char *errorMessagePtr;

	switch( keysetInfoPtr->type )
		{
		case KEYSET_HTTP:
			errorMessagePtr = keysetInfoPtr->keysetHTTP->errorMessage;
			break;

		case KEYSET_LDAP:
			errorMessagePtr = keysetInfoPtr->keysetLDAP->errorMessage;
			break;

		case KEYSET_DBMS:
			errorMessagePtr = keysetInfoPtr->keysetDBMS->errorMessage;
			break;

		default:
			errorMessagePtr = NULL;
		}
	if( errorMessagePtr != NULL )
		{
		va_list argPtr;

		va_start( argPtr, format );
		vsnprintf( errorMessagePtr, MAX_ERRMSG_SIZE, format, argPtr ); 
		va_end( argPtr );
		}
	assert( !cryptArgError( status ) );	/* Catch leaks */
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}

/* Prepare to update a keyset, performing various access checks and pre-
   processing of information */

typedef struct {
	CRYPT_KEYID_TYPE keyIDtype;		/* KeyID type */
	const void *keyID;				/* KeyID value */
	int keyIDlength;
	} KEYID_INFO;

static int initKeysetUpdate( KEYSET_INFO *keysetInfoPtr, 
							 KEYID_INFO *keyIDinfo, void *keyIDbuffer,
							 const BOOLEAN isRead )
	{
	/* If we're in the middle of a query, we can't do anything else */
	if( keysetInfoPtr->isBusyFunction != NULL && \
		keysetInfoPtr->isBusyFunction( keysetInfoPtr ) )
		return( exitErrorIncomplete( keysetInfoPtr, CRYPT_KEYINFO_QUERY ) );

	/* If we've been passed a full issuerAndSerialNumber as a key ID and the 
	   keyset needs an issuerID, convert it */
	if( keyIDinfo != NULL && \
		keyIDinfo->keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER && \
		( keysetInfoPtr->type == KEYSET_DBMS || \
		  ( keysetInfoPtr->type == KEYSET_FILE && \
		    keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 ) ) )
		{
		HASHFUNCTION hashFunction;
		int hashSize;

		/* Get the hash algorithm information */
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

		/* Hash the full iAndS to get an issuerID and use that for the keyID */
		hashFunction( NULL, keyIDbuffer, keyIDinfo->keyID, 
					  keyIDinfo->keyIDlength, HASH_ALL );
		keyIDinfo->keyIDtype = CRYPT_IKEYID_ISSUERID;
		keyIDinfo->keyID = keyIDbuffer;
		keyIDinfo->keyIDlength = hashSize;
		}

	/* If this is a read access, there's nothing further to do */
	if( isRead )
		return( CRYPT_OK );

	/* This is a write update, make sure that we can write to the keyset.  
	   This covers all possibilities, both keyset types for which writing 
	   isn't supported and individual keysets that we can't write to 
	   because of things like file permissions, so once we pass this check 
	   we know we can write to the keyset */
	if( keysetInfoPtr->options == CRYPT_KEYOPT_READONLY )
		return( CRYPT_ERROR_PERMISSION );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Flat-file Keyset Functions						*
*																			*
****************************************************************************/

/* Identify a flat-file keyset type */

#ifdef USE_PGP
  #if defined( INC_ALL )
	#include "pgp.h"
	#include "misc_rw.h"
  #else
	#include "envelope/pgp.h"
	#include "misc/misc_rw.h"
  #endif /* Compiler-specific includes */
#endif /* USE_PGP */

static KEYSET_SUBTYPE getKeysetType( STREAM *stream )
	{
	long length;
	int value, status;

	/* Try and guess the basic type */
	value = sPeek( stream );
	if( value == BER_SEQUENCE )
		{

		/* Read the length of the object.  This should be between 64 and 64K
		   bytes in size.  We have to allow for very tiny files to handle 
		   PKCS #15 files that contain only config data, and rather large 
		   ones to handle the existence of large numbers of trusted certs,
		   with a maximum of 32 objects * ~2K per object we can get close to
		   64K in size.  The length may also be zero if the indefinite 
		   encoding form is used.  Although PKCS #15 specifies the use of 
		   DER, it doesn't hurt to allow this at least for the outer wrapper.  
		   If Microsoft ever move to PKCS #15 they're bound to get it wrong */
		status = readLongSequence( stream, &length );
		if( cryptStatusError( status ) || \
			( length != CRYPT_UNUSED && ( length < 64 || length > 65535L ) ) )
			return( KEYSET_SUBTYPE_ERROR );

		/* Check for a PKCS #12/#15 file */
		if( peekTag( stream ) == BER_INTEGER )
			{
			long version;

			/* Check for a PKCS #12 version number */
			if( cryptStatusError( readShortInteger( stream, &version ) ) || \
				version != 3 )
				return( KEYSET_SUBTYPE_ERROR );
			return( KEYSET_SUBTYPE_PKCS12 );
			}

		/* Check for a PKCS #15 OID */
		if( !cryptStatusError( \
					readFixedOID( stream, OID_PKCS15_CONTENTTYPE ) ) )
			return( KEYSET_SUBTYPE_PKCS15 );

		/* It's something DER-encoded, but not PKCS #12 or PKCS #15 */
		return( KEYSET_SUBTYPE_ERROR );
		}
#ifdef USE_PGP
	if( getCTB( value ) == PGP_PACKET_PUBKEY || \
		getCTB( value ) == PGP_PACKET_SECKEY )
		{
		KEYSET_SUBTYPE type;

		/* Determine the file type based on the initial CTB */
		type = ( getCTB( value ) == PGP_PACKET_PUBKEY ) ? \
			   KEYSET_SUBTYPE_PGP_PUBLIC : KEYSET_SUBTYPE_PGP_PRIVATE;

		/* Perform a sanity check to make sure that the rest looks like a 
		   PGP keyring */
		status = pgpReadPacketHeader( stream, &value, &length );
		if( cryptStatusError( status ) )
			return( KEYSET_SUBTYPE_ERROR );
		if( type == KEYSET_SUBTYPE_PGP_PUBLIC )
			{
			if( length < 64 || length > 1024  )
				return( KEYSET_SUBTYPE_ERROR );
			}
		else
			if( length < 200 || length > 4096 )
				return( KEYSET_SUBTYPE_ERROR );
		value = sgetc( stream );
		if( value != PGP_VERSION_2 && value != PGP_VERSION_3 && \
			value != PGP_VERSION_OPENPGP )
			return( KEYSET_SUBTYPE_ERROR );
		return( type );
		}
#endif /* USE_PGP */

	/* "It doesn't look like anything from here" */
	return( KEYSET_SUBTYPE_ERROR );
	}

/* Open a flat-file keyset */

static int openKeysetStream( STREAM *stream, const char *name,
							 const CRYPT_KEYOPT_TYPE options,
							 CRYPT_KEYOPT_TYPE *keysetOptions, 
							 KEYSET_SUBTYPE *keysetSubType )
	{
	KEYSET_SUBTYPE subType = KEYSET_SUBTYPE_PKCS15;
	const int suffixPos = strlen( name ) - 4;
	int openMode, status;

	/* Get the expected subtype based on the keyset name */
	if( suffixPos > 0 && \
		( name[ suffixPos ] == '.' || name[ suffixPos ] == ' ' ) )
		{
		if( !strCompare( name + suffixPos + 1, "pgp", 3 ) || \
			!strCompare( name + suffixPos + 1, "gpg", 3 ) || \
			!strCompare( name + suffixPos + 1, "pkr", 3 ) )
			subType = KEYSET_SUBTYPE_PGP_PUBLIC;
		if( !strCompare( name + suffixPos + 1, "skr", 3 ) )
			subType = KEYSET_SUBTYPE_PGP_PRIVATE;
		if( !strCompare( name + suffixPos + 1, "pfx", 3 ) || \
			!strCompare( name + suffixPos + 1, "p12", 3 ) )
			subType = KEYSET_SUBTYPE_PKCS12;
		}

	/* If the file is read-only, put the keyset into read-only mode */
	if( fileReadonly( name ) )
		{
		/* If we want to create a new file, we can't do it if we don't have
		   write permission */
		if( options == CRYPT_KEYOPT_CREATE )
			return( CRYPT_ERROR_PERMISSION );

		/* Open the file in read-only mode */
		*keysetOptions = CRYPT_KEYOPT_READONLY;
		openMode = FILE_READ;
		}
	else
		/* If we're creating the file, open it in write-only mode.  Since
		   we'll (presumably) be storing private keys in it, we mark it as
		   both private (owner-access-only ACL) and sensitive (store in
		   secure storage if possible) */
		if( options == CRYPT_KEYOPT_CREATE )
			openMode = FILE_WRITE | FILE_EXCLUSIVE_ACCESS | \
					   FILE_PRIVATE | FILE_SENSITIVE;
		else
			/* Open it for read or read/write depending on whether the
			   readonly flag is set */
			openMode = ( options == CRYPT_KEYOPT_READONLY ) ? \
					   FILE_READ : FILE_READ | FILE_WRITE;
	if( options == CRYPT_IKEYOPT_EXCLUSIVEACCESS )
		openMode |= FILE_EXCLUSIVE_ACCESS;

	/* Pre-open the file containing the keyset.  This initially opens it in
	   read-only mode for auto-detection of the file type so we can check for
	   various problems */
	status = sFileOpen( stream, name, FILE_READ );
	if( cryptStatusError( status ) )
		{
		/* The file doesn't exist, if the create-new-file flag isn't set
		   return an error.  If it is set, make sure that we're trying to 
		   create a writeable keyset type */
		if( options != CRYPT_KEYOPT_CREATE )
			return( status );
		if( !isWriteableFileKeyset( subType ) )
			return( CRYPT_ERROR_NOTAVAIL );

		/* Try and create a new file */
		status = sFileOpen( stream, name, openMode );
		if( cryptStatusError( status ) )
			/* The file isn't open at this point so we have to exit 
			   explicitly rather than falling through to the error handler
			   below */
			return( status );
		}
	else
		{
		/* If we're opening an existing keyset, get its type and make sure
		   that it's valid */
		if( options != CRYPT_KEYOPT_CREATE )
			{
			BYTE buffer[ 512 ];

			sioctl( stream, STREAM_IOCTL_IOBUFFER, buffer, 512 );
			subType = getKeysetType( stream );
			if( subType == KEYSET_SUBTYPE_ERROR )
				{
				/* "It doesn't look like anything from here" */
				sFileClose( stream );
				return( CRYPT_ERROR_BADDATA );
				}
			sseek( stream, 0 );
			sioctl( stream, STREAM_IOCTL_IOBUFFER, NULL, 0 );
			}

		/* If it's a cryptlib keyset we can open it in any mode */
		if( isWriteableFileKeyset( subType ) )
			{
			/* If we're opening it something other than read-only mode, 
			   reopen it in that mode */
			if( openMode != FILE_READ )
				{
				sFileClose( stream );
				status = sFileOpen( stream, name, openMode );
				if( cryptStatusError( status ) )
					return( status );	/* Exit with file closed */
				}
			}
		else
			/* If it's a non-cryptlib keyset we can't open it for anything 
			   other than read-only access.  We return a not-available error 
			   rather than a permission error since this isn't a problem with
			   access permissions for the file but the fact that the code to
			   write the key doesn't exist */
			if( options != CRYPT_KEYOPT_READONLY )
				status = CRYPT_ERROR_NOTAVAIL;
		}
	if( cryptStatusError( status ) )
		sFileClose( stream );
	else
		*keysetSubType = subType;
	return( status );
	}

/****************************************************************************
*																			*
*						Keyset Attribute Handling Functions					*
*																			*
****************************************************************************/

/* Handle data sent to or read from a keyset object */

static int processGetAttribute( KEYSET_INFO *keysetInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	int *valuePtr = ( int * ) messageDataPtr;

	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_ERRORTYPE:
			*valuePtr = keysetInfoPtr->errorType;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORLOCUS:
			*valuePtr = keysetInfoPtr->errorLocus;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_INT_ERRORCODE:	
			switch( keysetInfoPtr->type )
				{
				case KEYSET_HTTP:
					*valuePtr = keysetInfoPtr->keysetHTTP->errorCode;
					break;

				case KEYSET_LDAP:
					*valuePtr = keysetInfoPtr->keysetLDAP->errorCode;
					break;

				case KEYSET_DBMS:
					*valuePtr = keysetInfoPtr->keysetDBMS->errorCode;
					break;

				default:
					*valuePtr = CRYPT_OK;
				}
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processGetAttributeS( KEYSET_INFO *keysetInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;

	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_INT_ERRORMESSAGE:
			{
			const char *errorMessagePtr;

			switch( keysetInfoPtr->type )
				{
				case KEYSET_HTTP:
					errorMessagePtr = keysetInfoPtr->keysetHTTP->errorMessage;
					break;

				case KEYSET_LDAP:
					errorMessagePtr = keysetInfoPtr->keysetLDAP->errorMessage;
					break;

				case KEYSET_DBMS:
					errorMessagePtr = keysetInfoPtr->keysetDBMS->errorMessage;
					break;

				default:
					errorMessagePtr = "";
				}
			if( !*errorMessagePtr )
				return( exitErrorNotFound( keysetInfoPtr,
										   CRYPT_ATTRIBUTE_INT_ERRORMESSAGE ) );
			return( attributeCopy( msgData, errorMessagePtr,
								   strlen( errorMessagePtr ) ) );
			}

		case CRYPT_IATTRIBUTE_CONFIGDATA:
		case CRYPT_IATTRIBUTE_USERINDEX:
		case CRYPT_IATTRIBUTE_USERINFO:
		case CRYPT_IATTRIBUTE_TRUSTEDCERT:
		case CRYPT_IATTRIBUTE_TRUSTEDCERT_NEXT:
			/* It's encoded cryptlib-specific data, fetch it from to the
			   keyset */
			assert( keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );
			return( keysetInfoPtr->getItemFunction( keysetInfoPtr, NULL,
									KEYMGMT_ITEM_DATA, CRYPT_KEYID_NONE,
									NULL, 0, msgData->data, &msgData->length,
									messageValue ) );

		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttribute( KEYSET_INFO *keysetInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	switch( messageValue )
		{
		case MESSAGE_SETATTRIBUTE:
			/* It's an initialisation message, there's nothing to do */
			assert( *( int * ) messageDataPtr == CRYPT_IATTRIBUTE_INITIALISED );
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

static int processSetAttributeS( KEYSET_INFO *keysetInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	int status;

	switch( messageValue )
		{
		case CRYPT_KEYINFO_QUERY:
		case CRYPT_KEYINFO_QUERY_REQUESTS:
			assert( keysetInfoPtr->getFirstItemFunction != NULL );
			assert( keysetInfoPtr->isBusyFunction != NULL );

			/* If we're in the middle of an existing query the user needs to
			   cancel it before starting another one */
			if( keysetInfoPtr->isBusyFunction( keysetInfoPtr ) && \
				( msgData->length != 6 || \
				  strCompare( msgData->data, "cancel", msgData->length ) ) )
				return( exitErrorIncomplete( keysetInfoPtr, messageValue ) );

			/* Send the query to the data source */
			return( keysetInfoPtr->getFirstItemFunction( keysetInfoPtr, NULL,
						NULL, CRYPT_KEYID_NAME, msgData->data, msgData->length,
						( messageValue == CRYPT_KEYINFO_QUERY_REQUESTS ) ? \
							KEYMGMT_ITEM_REQUEST : KEYMGMT_ITEM_PUBLICKEY,
						KEYMGMT_FLAG_NONE ) );

		case CRYPT_IATTRIBUTE_CONFIGDATA:
		case CRYPT_IATTRIBUTE_USERINDEX:
		case CRYPT_IATTRIBUTE_USERID:
		case CRYPT_IATTRIBUTE_USERINFO:
			/* It's encoded cryptlib-specific data, pass it through to the
			   keyset */
			assert( keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );
			assert( keysetInfoPtr->setItemFunction != NULL );
			status = keysetInfoPtr->setItemFunction( keysetInfoPtr,
							CRYPT_UNUSED, KEYMGMT_ITEM_DATA,
							msgData->data, msgData->length, messageValue );
			if( cryptStatusOK( status ) && \
				messageValue != CRYPT_IATTRIBUTE_USERID )
				{
				/* The update succeeded, remember that the data in the keyset
				   has changed, unless it's a userID that just modifies
				   existing data */
				keysetInfoPtr->flags |= KEYSET_DIRTY;
				keysetInfoPtr->flags &= ~KEYSET_EMPTY;
				}
			return( status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*								Keyset Message Handler						*
*																			*
****************************************************************************/

/* Handle a message sent to a keyset object */

static int keysetMessageFunction( const void *objectInfoPtr,
								  const MESSAGE_TYPE message,
								  void *messageDataPtr,
								  const int messageValue )
	{
	KEYSET_INFO *keysetInfoPtr = ( KEYSET_INFO * ) objectInfoPtr;

	/* Process the destroy object message */
	if( message == MESSAGE_DESTROY )
		{
		/* If the keyset is active, perform any required cleanup functions */
		if( keysetInfoPtr->flags & KEYSET_OPEN )
			{
			/* Shut down the keyset if required */
			if( keysetInfoPtr->shutdownFunction != NULL )
				keysetInfoPtr->shutdownFunction( keysetInfoPtr );

			/* If the keyset is implemented as a file, close it (the keyset-
			   specific handler sees only an I/O stream and doesn't perform
			   any file-level functions).  Because we cache all information
			   in a PKCS #12/#15 keyset and close the stream immediately
			   afterwards if we've opened it in read-only mode, we only
			   close the underlying stream for a PKCS #12/#15 keyset if it's 
			   still active.  Note the distinction between the keyset being 
			   active and the stream being active, for PKCS #12/#15 the 
			   keyset can be active without being associated with an open 
			   stream */
			if( keysetInfoPtr->flags & KEYSET_STREAM_OPEN )
				{
				/* Since the update may have changed the overall size, we
				   need to clear any leftover data from the previous
				   version of the keyset before we close the file */
				if( keysetInfoPtr->flags & KEYSET_DIRTY )
					fileClearToEOF( &keysetInfoPtr->keysetFile->stream );
				sFileClose( &keysetInfoPtr->keysetFile->stream );

				/* If it's a newly-created empty keyset file or one in which 
				   all the keys have been deleted, remove it.  This situation
				   can occur if there's some sort of error on writing and no 
				   keys are ever written to the keyset */
				if( keysetInfoPtr->flags & KEYSET_EMPTY )
					fileErase( keysetInfoPtr->keysetFile->fileName );
				}
			}

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		assert( message == MESSAGE_GETATTRIBUTE || \
				message == MESSAGE_GETATTRIBUTE_S || \
				message == MESSAGE_SETATTRIBUTE || \
				message == MESSAGE_SETATTRIBUTE_S );


		/* If it's a keyset-specific attribute, forward it directly to
		   the low-level code */
		if( messageValue >= CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS && \
			messageValue <= CRYPT_OPTION_KEYS_LDAP_EMAILNAME )
			{
			int status;

			if( message == MESSAGE_SETATTRIBUTE || \
				message == MESSAGE_SETATTRIBUTE_S )
				{
				assert( keysetInfoPtr->setAttributeFunction != NULL );

				status = keysetInfoPtr->setAttributeFunction( keysetInfoPtr,
											messageDataPtr, messageValue );
				if( status == CRYPT_ERROR_INITED )
					return( exitError( keysetInfoPtr, messageValue,
									   CRYPT_ERRTYPE_ATTR_PRESENT,
									   CRYPT_ERROR_INITED ) );
				}
			else
				{
				assert( message == MESSAGE_GETATTRIBUTE || \
						message == MESSAGE_GETATTRIBUTE_S );
				assert( keysetInfoPtr->getAttributeFunction != NULL );

				status = keysetInfoPtr->getAttributeFunction( keysetInfoPtr,
											messageDataPtr, messageValue );
				if( status == CRYPT_ERROR_NOTFOUND )
					return( exitErrorNotFound( keysetInfoPtr, 
											   messageValue ) );
				}
			return( status );
			}

		if( message == MESSAGE_GETATTRIBUTE )
			return( processGetAttribute( keysetInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE_S )
			return( processGetAttributeS( keysetInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE )
			return( processSetAttribute( keysetInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE_S )
			return( processSetAttributeS( keysetInfoPtr, messageDataPtr,
										  messageValue ) );

		assert( NOTREACHED );
		return( CRYPT_ERROR );	/* Get rid of compiler warning */
		}

	/* Process messages that check a keyset */
	if( message == MESSAGE_CHECK )
		{
		/* The check for whether this keyset type can contain an object that 
		   can perform the requested operation has already been performed by 
		   the kernel, so there's nothing further to do here */
		assert( ( messageValue != MESSAGE_CHECK_PKC_PRIVATE && \
				  messageValue != MESSAGE_CHECK_PKC_DECRYPT && \
				  messageValue != MESSAGE_CHECK_PKC_DECRYPT_AVAIL && \
				  messageValue != MESSAGE_CHECK_PKC_SIGN && \
				  messageValue != MESSAGE_CHECK_PKC_SIGN_AVAIL ) || 
				( keysetInfoPtr->type != KEYSET_DBMS && \
				  keysetInfoPtr->type != KEYSET_LDAP && \
				  keysetInfoPtr->type != KEYSET_HTTP ) );

		return( CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == MESSAGE_KEY_GETKEY )
		{
		MESSAGE_KEYMGMT_INFO *getkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		CONST_INIT_STRUCT_3( KEYID_INFO keyIDinfo, \
							 getkeyInfo->keyIDtype, getkeyInfo->keyID, \
							 getkeyInfo->keyIDlength );
		BYTE keyIDbuffer[ KEYID_SIZE ];
		int status;

		CONST_SET_STRUCT( keyIDinfo.keyIDtype = getkeyInfo->keyIDtype; \
						  keyIDinfo.keyID = getkeyInfo->keyID; \
						  keyIDinfo.keyIDlength = getkeyInfo->keyIDlength );

		assert( keysetInfoPtr->getItemFunction != NULL );
		assert( keyIDinfo.keyIDtype != CRYPT_KEYID_NONE && \
				keyIDinfo.keyID != NULL && keyIDinfo.keyIDlength > 0 );
		assert( messageValue != KEYMGMT_ITEM_PRIVATEKEY || \
				keysetInfoPtr->type == KEYSET_FILE );
		assert( ( messageValue != KEYMGMT_ITEM_SECRETKEY && \
				  messageValue != KEYMGMT_ITEM_DATA ) || \
				( keysetInfoPtr->type == KEYSET_FILE && \
				  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 ) );
		assert( ( messageValue != KEYMGMT_ITEM_REQUEST && \
				  messageValue != KEYMGMT_ITEM_REVOCATIONINFO && \
				  messageValue != KEYMGMT_ITEM_PKIUSER ) || \
				keysetInfoPtr->type == KEYSET_DBMS );

		/* Get the key */
		status = initKeysetUpdate( keysetInfoPtr, &keyIDinfo, keyIDbuffer,
								   TRUE );
		if( cryptStatusOK( status ) )
			status = keysetInfoPtr->getItemFunction( keysetInfoPtr,
								&getkeyInfo->cryptHandle, messageValue,
								keyIDinfo.keyIDtype, keyIDinfo.keyID, 
								keyIDinfo.keyIDlength, getkeyInfo->auxInfo, 
								&getkeyInfo->auxInfoLength, 
								getkeyInfo->flags );
		return( status );
		}
	if( message == MESSAGE_KEY_SETKEY )
		{
		MESSAGE_KEYMGMT_INFO *setkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		int status;

		assert( keysetInfoPtr->setItemFunction != NULL );
		assert( messageValue != KEYMGMT_ITEM_PRIVATEKEY || \
				( keysetInfoPtr->type == KEYSET_FILE && \
				  ( keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 || \
					keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS12 ) ) );
		assert( ( messageValue != KEYMGMT_ITEM_SECRETKEY && \
				  messageValue != KEYMGMT_ITEM_DATA ) || \
				( keysetInfoPtr->type == KEYSET_FILE && \
				  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 ) );
		assert( ( messageValue != KEYMGMT_ITEM_REQUEST && \
				  messageValue != KEYMGMT_ITEM_REVOCATIONINFO && \
				  messageValue != KEYMGMT_ITEM_PKIUSER ) || \
				( keysetInfoPtr->type == KEYSET_DBMS ) );

		/* Set the key.  This is currently the only way to associate a cert
		   with a context (that is, it's not possible to add a cert to an
		   existing context directly).  At first glance this should be 
		   possible since the required access checks are performed by the 
		   kernel: The object is of the correct type (a certificate), in the 
		   high state (it's been signed), and the cert owner and context 
		   owner are the same.  However, the process of attaching the cert to
		   the context is quite tricky.  The cert will have a public-key 
		   context already attached to it from when the cert was created or 
		   imported.  In order to attach this to the other context, we need 
		   to first destroy the context associated with the cert and then 
		   replace it with the other context.  This procedure is both messy 
		   and non-atomic.  There are also complications surrounding use 
		   with devices, where contexts are really cryptlib objects but just 
		   dummy values that point back to the object for handling of 
		   operations.  Going via a keyset/device bypasses these issues, but 
		   doing it directly shows up all of these problems */
		status = initKeysetUpdate( keysetInfoPtr, NULL, NULL, FALSE );
		if( cryptStatusOK( status ) )
			status = keysetInfoPtr->setItemFunction( keysetInfoPtr,
							setkeyInfo->cryptHandle, messageValue,
							setkeyInfo->auxInfo, setkeyInfo->auxInfoLength,
							setkeyInfo->flags );
		if( cryptStatusOK( status ) )
			{
			/* The update succeeded, remember that the data in the keyset has
			   changed */
			keysetInfoPtr->flags |= KEYSET_DIRTY;
			keysetInfoPtr->flags &= ~KEYSET_EMPTY;
			}
		return( status );
		}
	if( message == MESSAGE_KEY_DELETEKEY )
		{
		MESSAGE_KEYMGMT_INFO *deletekeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		CONST_INIT_STRUCT_3( KEYID_INFO keyIDinfo, \
							 deletekeyInfo->keyIDtype, deletekeyInfo->keyID, \
							 deletekeyInfo->keyIDlength );
		BYTE keyIDbuffer[ KEYID_SIZE ];
		int status;

		CONST_SET_STRUCT( keyIDinfo.keyIDtype = deletekeyInfo->keyIDtype; \
						  keyIDinfo.keyID = deletekeyInfo->keyID; \
						  keyIDinfo.keyIDlength = deletekeyInfo->keyIDlength );

		assert( keysetInfoPtr->deleteItemFunction != NULL );
		assert( keyIDinfo.keyIDtype != CRYPT_KEYID_NONE && \
				keyIDinfo.keyID != NULL && keyIDinfo.keyIDlength > 0 );

		/* Delete the key */
		status = initKeysetUpdate( keysetInfoPtr, &keyIDinfo, keyIDbuffer,
								   FALSE );
		if( cryptStatusOK( status ) )
			status = keysetInfoPtr->deleteItemFunction( keysetInfoPtr,
								messageValue, keyIDinfo.keyIDtype, 
								keyIDinfo.keyID, keyIDinfo.keyIDlength );
		if( cryptStatusOK( status ) )
			/* The update succeeded, remember that the data in the keyset has
			   changed */
			keysetInfoPtr->flags |= KEYSET_DIRTY;
		return( status );
		}
	if( message == MESSAGE_KEY_GETFIRSTCERT )
		{
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		CONST_INIT_STRUCT_3( KEYID_INFO keyIDinfo, \
							 getnextcertInfo->keyIDtype, getnextcertInfo->keyID, \
							 getnextcertInfo->keyIDlength );
		BYTE keyIDbuffer[ KEYID_SIZE ];
		int status;

		CONST_SET_STRUCT( keyIDinfo.keyIDtype = getnextcertInfo->keyIDtype; \
						  keyIDinfo.keyID = getnextcertInfo->keyID; \
						  keyIDinfo.keyIDlength = getnextcertInfo->keyIDlength );

		assert( keysetInfoPtr->getFirstItemFunction != NULL );
		assert( keyIDinfo.keyIDtype != CRYPT_KEYID_NONE && \
				keyIDinfo.keyID != NULL && keyIDinfo.keyIDlength > 0 );
		assert( getnextcertInfo->auxInfo == NULL || \
				getnextcertInfo->auxInfoLength == sizeof( int ) );

		/* Fetch the first cert in a sequence from the keyset */
		status = initKeysetUpdate( keysetInfoPtr, &keyIDinfo, keyIDbuffer, 
								   TRUE );
		if( cryptStatusOK( status ) )
			status = keysetInfoPtr->getFirstItemFunction( keysetInfoPtr,
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						keyIDinfo.keyIDtype, keyIDinfo.keyID,
						keyIDinfo.keyIDlength, messageValue,
						getnextcertInfo->flags );
		return( status );
		}
	if( message == MESSAGE_KEY_GETNEXTCERT )
		{
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		assert( keysetInfoPtr->getNextItemFunction != NULL );
		assert( getnextcertInfo->keyIDtype == CRYPT_KEYID_NONE && \
				getnextcertInfo->keyID == NULL && \
				getnextcertInfo->keyIDlength == 0 );
		assert( getnextcertInfo->auxInfo == NULL || \
				getnextcertInfo->auxInfoLength == sizeof( int ) );

		/* Fetch the next cert in a sequence from the keyset */
		return( keysetInfoPtr->getNextItemFunction( keysetInfoPtr,
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						getnextcertInfo->flags ) );
		}
	if( message == MESSAGE_KEY_CERTMGMT )
		{
		MESSAGE_CERTMGMT_INFO *certMgmtInfo = \
								( MESSAGE_CERTMGMT_INFO * ) messageDataPtr;
		int status;

		assert( keysetInfoPtr->keysetDBMS->certMgmtFunction != NULL );
		assert( messageValue >= CRYPT_CERTACTION_CERT_CREATION && \
				messageValue <= CRYPT_CERTACTION_LAST_USER );
		assert( keysetInfoPtr->isBusyFunction != NULL );

		/* Perform the cert management operation */
		status = initKeysetUpdate( keysetInfoPtr, NULL, NULL, TRUE );
		if( cryptStatusOK( status ) )
			status = keysetInfoPtr->keysetDBMS->certMgmtFunction( keysetInfoPtr,
						( certMgmtInfo->cryptCert != CRYPT_UNUSED ) ? \
						&certMgmtInfo->cryptCert : NULL, certMgmtInfo->caKey,
						certMgmtInfo->request, messageValue );
		if( cryptStatusOK( status ) )
			/* The update succeeded, remember that the data in the keyset has
			   changed */
			keysetInfoPtr->flags |= KEYSET_DIRTY;
		return( status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Open a keyset.  This is a low-level function encapsulated by createKeyset()
   and used to manage error exits */

static int openKeyset( CRYPT_KEYSET *iCryptKeyset,
					   const CRYPT_USER cryptOwner,
					   const CRYPT_KEYSET_TYPE keysetType,
					   const char *name, const CRYPT_KEYOPT_TYPE options,
					   KEYSET_INFO **keysetInfoPtrPtr )
	{
	KEYSET_INFO *keysetInfoPtr;
	STREAM stream;
	CRYPT_KEYOPT_TYPE localOptions = options;
	KEYSET_SUBTYPE keysetSubType;
	int subType, storageSize, status;

	/* Clear the return values */
	*iCryptKeyset = CRYPT_ERROR;
	*keysetInfoPtrPtr = NULL;

	/* Perform general checks that can be done before we create the object */
	if( ( keysetType == CRYPT_KEYSET_HTTP && \
		  options != CRYPT_KEYOPT_READONLY ) || \
		( keysetType == CRYPT_KEYSET_LDAP && \
		  options == CRYPT_KEYOPT_CREATE ) )
		/* We can't open an HTTP keyset for anything other than read-only
		   access, and we can't create an LDAP directory */
		return( CRYPT_ERROR_PERMISSION );
	if( keysetType == CRYPT_KEYSET_FILE && \
		strlen( name ) > MAX_PATH_LENGTH - 1 )
		return( CRYPT_ARGERROR_STR1 );

	/* Set up subtype-specific information */
	switch( keysetType )
		{
		case CRYPT_KEYSET_FILE:
			subType = SUBTYPE_KEYSET_FILE_PARTIAL;
			storageSize = sizeof( FILE_INFO );
			break;

		case CRYPT_KEYSET_HTTP:
			subType = SUBTYPE_KEYSET_HTTP;
			storageSize = sizeof( HTTP_INFO );
			break;

		case CRYPT_KEYSET_LDAP:
			subType = SUBTYPE_KEYSET_LDAP;
			storageSize = sizeof( LDAP_INFO );
			break;

		case CRYPT_KEYSET_ODBC:
		case CRYPT_KEYSET_DATABASE:
		case CRYPT_KEYSET_PLUGIN:
			subType = SUBTYPE_KEYSET_DBMS;
			storageSize = sizeof( DBMS_INFO );
			break;

		case CRYPT_KEYSET_ODBC_STORE:
		case CRYPT_KEYSET_DATABASE_STORE:
		case CRYPT_KEYSET_PLUGIN_STORE:
			subType = SUBTYPE_KEYSET_DBMS_STORE;
			storageSize = sizeof( DBMS_INFO );
			break;
		
		default:
			assert( NOTREACHED );
			return( CRYPT_ARGERROR_NUM1 );
		}

	/* If it's a flat-file keyset which is implemented on top of an I/O 
	   stream, make sure that we can open the stream before we try and 
	   create the keyset object */
	if( keysetType == CRYPT_KEYSET_FILE )
		{
		status = openKeysetStream( &stream, name, options, &localOptions, 
								   &keysetSubType );
		if( cryptStatusError( status ) )
			return( status );
		
		/* If the keyset contains the full set of search keys and index
		   information needed to handle all keyset operations (e.g. cert 
		   chain building, query by key usage types) we mark it as a full-
		   function keyset with the same functionality as a DBMS keyset, 
		   rather than just a generic flat-file store */
		if( keysetSubType == KEYSET_SUBTYPE_PKCS15 )
			subType = SUBTYPE_KEYSET_FILE;
		}

	/* Create the keyset object */
	status = krnlCreateObject( ( void ** ) &keysetInfoPtr, 
							   sizeof( KEYSET_INFO ) + storageSize, 
							   OBJECT_TYPE_KEYSET, subType, 
							   CREATEOBJECT_FLAG_NONE, cryptOwner, 
							   ACTION_PERM_NONE_ALL, keysetMessageFunction );
	if( cryptStatusError( status ) )
		{
		if( keysetType == CRYPT_KEYSET_FILE )
			sFileClose( &stream );
		return( status );
		}
	*keysetInfoPtrPtr = keysetInfoPtr;
	*iCryptKeyset = keysetInfoPtr->objectHandle = status;
	keysetInfoPtr->ownerHandle = cryptOwner;
	keysetInfoPtr->options = localOptions;
	switch( keysetType )
		{
		case CRYPT_KEYSET_FILE:
			keysetInfoPtr->type = KEYSET_FILE;
			keysetInfoPtr->keysetFile = ( FILE_INFO * ) keysetInfoPtr->storage;
			break;

		case CRYPT_KEYSET_HTTP:
			keysetInfoPtr->type = KEYSET_HTTP;
			keysetInfoPtr->keysetHTTP = ( HTTP_INFO * ) keysetInfoPtr->storage;
			break;

		case CRYPT_KEYSET_LDAP:
			keysetInfoPtr->type = KEYSET_LDAP;
			keysetInfoPtr->keysetLDAP = ( LDAP_INFO * ) keysetInfoPtr->storage;
			break;

		default:
			keysetInfoPtr->type = KEYSET_DBMS;
			keysetInfoPtr->keysetDBMS = ( DBMS_INFO * ) keysetInfoPtr->storage;
			break;
		}
	keysetInfoPtr->storageSize = storageSize;

	/* If it's a flat-file keyset which is implemented on top of an I/O 
	   stream, handle it specially */
	if( keysetType == CRYPT_KEYSET_FILE )
		{
		/* Remember the key file's name and I/O stream */
		keysetInfoPtr->subType = keysetSubType;
		strcpy( keysetInfoPtr->keysetFile->fileName, name );
		keysetInfoPtr->keysetFile->stream = stream;

		/* Set up the access information for the file */
		switch( keysetInfoPtr->subType )
			{
			case KEYSET_SUBTYPE_PKCS12:
				status = setAccessMethodPKCS12( keysetInfoPtr );
				break;

			case KEYSET_SUBTYPE_PKCS15:
				status = setAccessMethodPKCS15( keysetInfoPtr );
				break;

			case KEYSET_SUBTYPE_PGP_PUBLIC:
				status = setAccessMethodPGPPublic( keysetInfoPtr );
				break;

			case KEYSET_SUBTYPE_PGP_PRIVATE:
				status = setAccessMethodPGPPrivate( keysetInfoPtr );
				break;

			default:
				assert( NOTREACHED );
				status = CRYPT_ERROR;
			}
		if( cryptStatusOK( status ) )
			{
			BYTE buffer[ STREAM_BUFSIZE ];

			assert( keysetInfoPtr->initFunction != NULL && \
					keysetInfoPtr->getItemFunction != NULL );
			assert( subType != SUBTYPE_KEYSET_FILE || \
					( keysetInfoPtr->setItemFunction != NULL && \
					  keysetInfoPtr->deleteItemFunction != NULL && \
					  keysetInfoPtr->getFirstItemFunction != NULL && \
					  keysetInfoPtr->getNextItemFunction != NULL ) );

			sioctl( &keysetInfoPtr->keysetFile->stream, 
					STREAM_IOCTL_IOBUFFER, buffer, STREAM_BUFSIZE );
			status = keysetInfoPtr->initFunction( keysetInfoPtr, NULL,
												  keysetInfoPtr->options );
			sioctl( &keysetInfoPtr->keysetFile->stream, 
					STREAM_IOCTL_IOBUFFER, NULL, 0 );
			}
		if( cryptStatusError( status ) )
			{
			sFileClose( &keysetInfoPtr->keysetFile->stream );
			if( options == CRYPT_KEYOPT_CREATE )
				/* It's a newly-created file, make sure that we don't leave 
				   it lying around on disk */
				fileErase( keysetInfoPtr->keysetFile->fileName );
			return( status );
			}
		if( ( keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS12 || \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 || \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PGP_PRIVATE ) && \
			( keysetInfoPtr->options == CRYPT_KEYOPT_READONLY ) )
			/* If we've got the keyset open in read-only mode we don't need 
			   to touch it again since everything is cached in-memory, so we 
			   can close the file stream */
			sFileClose( &keysetInfoPtr->keysetFile->stream );
		else
			keysetInfoPtr->flags |= KEYSET_STREAM_OPEN;
		keysetInfoPtr->flags |= KEYSET_OPEN;
		if( keysetInfoPtr->options == CRYPT_KEYOPT_CREATE )
			keysetInfoPtr->flags |= KEYSET_EMPTY;
		return( CRYPT_OK );
		}

	/* Wait for any async keyset driver binding to complete.  We do this as 
	   late as possible to prevent file keyset reads that occur on startup 
	   (for example to get config options) from stalling the startup 
	   process */
	krnlWaitSemaphore( SEMAPHORE_DRIVERBIND );

	/* It's a specific type of keyset, set up the access information for it
	   and connect to it */
	switch( keysetType )
		{
		case CRYPT_KEYSET_ODBC:
		case CRYPT_KEYSET_DATABASE:
		case CRYPT_KEYSET_PLUGIN:
		case CRYPT_KEYSET_ODBC_STORE:
		case CRYPT_KEYSET_DATABASE_STORE:
		case CRYPT_KEYSET_PLUGIN_STORE:
			status = setAccessMethodDBMS( keysetInfoPtr, keysetType );
			break;

		case CRYPT_KEYSET_HTTP:
			status = setAccessMethodHTTP( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_LDAP:
			status = setAccessMethodLDAP( keysetInfoPtr );
			break;

		default:
			assert( NOTREACHED );
		}
	if( cryptStatusOK( status ) )
		{
		assert( keysetInfoPtr->initFunction != NULL && \
				keysetInfoPtr->getItemFunction != NULL );
		assert( keysetType == CRYPT_KEYSET_HTTP || \
				( keysetInfoPtr->setItemFunction != NULL && \
				  keysetInfoPtr->deleteItemFunction != NULL && \
				  keysetInfoPtr->isBusyFunction != NULL ) );
		assert( keysetType == CRYPT_KEYSET_HTTP || \
				keysetType == CRYPT_KEYSET_LDAP || \
				( keysetInfoPtr->getFirstItemFunction != NULL && \
				  keysetInfoPtr->getNextItemFunction != NULL ) );

		status = keysetInfoPtr->initFunction( keysetInfoPtr, name, 
											  keysetInfoPtr->options );
		}
	if( cryptStatusOK( status ) )
		{
		keysetInfoPtr->flags |= KEYSET_OPEN;
		if( keysetInfoPtr->options == CRYPT_KEYOPT_CREATE )
			keysetInfoPtr->flags |= KEYSET_EMPTY;
		}
	return( status );
	}

/* Create a keyset object */

int createKeyset( MESSAGE_CREATEOBJECT_INFO *createInfo,
				  const void *auxDataPtr, const int auxValue )
	{
	CRYPT_KEYSET iCryptKeyset;
	const CRYPT_KEYSET_TYPE keysetType = createInfo->arg1;
	const CRYPT_KEYOPT_TYPE options = createInfo->arg2;
	KEYSET_INFO *keysetInfoPtr;
	char nameBuffer[ MAX_ATTRIBUTE_SIZE + 1 ];
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( keysetType <= CRYPT_KEYSET_NONE || keysetType >= CRYPT_KEYSET_LAST )
		return( CRYPT_ARGERROR_NUM1 );
	if( createInfo->strArgLen1 < MIN_NAME_LENGTH || \
		createInfo->strArgLen1 >= MAX_ATTRIBUTE_SIZE )
		return( CRYPT_ARGERROR_STR1 );
	memcpy( nameBuffer, createInfo->strArg1, createInfo->strArgLen1 );
	nameBuffer[ createInfo->strArgLen1 ] = '\0';
	if( options < CRYPT_KEYOPT_NONE || options >= CRYPT_KEYOPT_LAST )
		/* CRYPT_KEYOPT_NONE is a valid setting for this parameter */
		return( CRYPT_ARGERROR_NUM2 );

	/* Pass the call on to the lower-level open function */
	initStatus = openKeyset( &iCryptKeyset, createInfo->cryptOwner,
							 keysetType, nameBuffer, options,
							 &keysetInfoPtr );
	if( keysetInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The init failed, make sure that the object gets destroyed when we 
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptKeyset, IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( iCryptKeyset, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptKeyset;
	return( CRYPT_OK );
	}

/* Generic management function for this class of object */

int keysetManagementFunction( const MANAGEMENT_ACTION_TYPE action )
	{
	static int initLevel = 0;
	int status;

	assert( action == MANAGEMENT_ACTION_INIT || \
			action == MANAGEMENT_ACTION_SHUTDOWN );

	switch( action )
		{
		case MANAGEMENT_ACTION_INIT:
			status = dbxInitODBC();
			if( cryptStatusOK( status ) )
				{
				initLevel++;
				status = dbxInitLDAP();
				}
			if( cryptStatusOK( status ) )
				initLevel++;
			return( status );

		case MANAGEMENT_ACTION_SHUTDOWN:
			if( initLevel > 1 )
				dbxEndLDAP();
			if( initLevel > 0 )
				dbxEndODBC();
			initLevel = 0;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}
#endif /* USE_KEYSETS */
