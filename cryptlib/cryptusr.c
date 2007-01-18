/****************************************************************************
*																			*
*							cryptlib User Routines							*
*						Copyright Peter Gutmann 1999-2006					*
*																			*
****************************************************************************/

#include <stdio.h>		/* For snprintf() */
#include "crypt.h"
#ifdef INC_ALL
  #include "trustmgr.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "cert/trustmgr.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* States for the user object */

typedef enum {
	USER_STATE_NONE,				/* No initialisation state */
	USER_STATE_SOINITED,			/* SSO inited, not usable */
	USER_STATE_USERINITED,			/* User inited, usable */
	USER_STATE_LOCKED,				/* Disabled, not usable */
	USER_STATE_LAST					/* Last possible state */
	} USER_STATE_TYPE;

/* The structure which stores the information on a user */

typedef struct UI {
	/* Control and status information */
	CRYPT_USER_TYPE type;			/* User type */
	USER_STATE_TYPE state;			/* User object state */
	BYTE userName[ CRYPT_MAX_TEXTSIZE + 8 ];
	int userNameLength;				/* User name */
	BYTE userID[ KEYID_SIZE + 8 ], creatorID[ KEYID_SIZE + 8 ];
									/* ID of user and creator of this user */
	int fileRef;					/* User info keyset reference */

	/* Configuration options for this user.  These aren't handled directly by
	   the user object code but are managed externally through the config
	   code, so they're just treated as a dynamically-allocated blob within
	   the user object */
	void *configOptions;

	/* Certificate trust information for this user, and a flag indicating
	   whether the trust info has changed and potentially needs to be
	   committed to disk */
	void *trustInfoPtr;
	BOOLEAN trustInfoChanged;

	/* The user object contains an associated keyset which is used to store
	   user information to disk, in addition for SOs and CAs it also contains
	   an associated encryption context, either a private key (for an SO) or
	   a conventional key (for a CA) */
	CRYPT_KEYSET iKeyset;			/* Keyset */
	CRYPT_CONTEXT iCryptContext;	/* Private/secret key */

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* The object's handle, used when sending messages to the object when
	   only the xxx_INFO is available */
	CRYPT_HANDLE objectHandle;
	} USER_INFO;

/* User information as read from the user info file */

typedef struct {
	CRYPT_USER_TYPE type;			/* User type */
	USER_STATE_TYPE state;			/* User state */
	BYTE userName[ CRYPT_MAX_TEXTSIZE + 8 ];
	int userNameLength;				/* User name */
	BYTE userID[ KEYID_SIZE + 8 ];	/* User ID */
	BYTE creatorID[ KEYID_SIZE + 8 ];/* Creator ID */
	int fileRef;					/* User info file reference */
	} USER_FILE_INFO;

/* Default and primary SO user info.  The default user is a special type
   which has both normal user and SO privileges.  This is because in its
   usual usage mode where cryptlib is functioning as a single-user system
   the user doesn't know about the existence of user objects and just wants
   everything to work the way they expect.  Because of this, the default user
   has to be able to perform the full range of available operations,
   requiring that they appear as both a normal user and an SO.

   For now the default user is marked as an SO user because the kernel checks
   don't allow dual-type objects and some operations require that the user be
   at least an SO user, once a distinction is made between SOs and users this
   will need to be fixed */

static const USER_FILE_INFO FAR_BSS defaultUserInfo = {
#if 0	/* Disabled since ACL checks are messed up by dual-user, 18/5/02 */
	CRYPT_USER_NONE,				/* Special-case SO+normal user */
#else
	CRYPT_USER_SO,					/* Special-case SO user */
#endif /* 0 */
	USER_STATE_USERINITED,			/* Initialised, ready for use */
	"Default cryptlib user", 21,	/* Pre-set user name */
	"<<<<DEFAULT_USER>>>>", "<<<<DEFAULT_USER>>>>",
	CRYPT_UNUSED					/* No corresponding user file */
	};
static const USER_FILE_INFO FAR_BSS primarySOInfo = {
	CRYPT_USER_SO,					/* SO user */
	USER_STATE_SOINITED,			/* SO initialised, not ready for use */
	"Security officer", 16,			/* Pre-set user name */
	"<<<PRIMARYSO_USER>>>", "<<<TETRAGRAMMATON>>>",
	-1			/* No user file when starting from zeroised state */
	};

/* The primary SO password after zeroisation */

#define PRIMARYSO_PASSWORD		"zeroised"
#define PRIMARYSO_ALTPASSWORD	"zeroized"
#define PRIMARYSO_PASSWORD_LENGTH 8

/* Prototypes for functions in cryptcfg.c */

int initOptions( void **configOptionsPtr );
void endOptions( void *configOptions );
int setOption( void *configOptions, const CRYPT_ATTRIBUTE_TYPE option,
			   const int value );
int setOptionString( void *configOptions, const CRYPT_ATTRIBUTE_TYPE option,
					 const char *value, const int valueLength );
int getOption( void *configOptions, const CRYPT_ATTRIBUTE_TYPE option );
char *getOptionString( void *configOptions,
					   const CRYPT_ATTRIBUTE_TYPE option );
int readConfig( const CRYPT_USER iCryptUser, const char *fileName,
				void *trustInfoPtr );
int encodeConfigData( void *configOptions, const char *fileName,
					  void *trustInfoPtr, void **data, int *length );
int commitConfigData( const CRYPT_USER cryptUser, const char *fileName,
					  const void *data, const int length );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* The maximum size of the index data for a user, ~128 bytes, and for the
   fixed user information */

#define MAX_USERINDEX_SIZE	( 16 + ( KEYID_SIZE * 2 ) + CRYPT_MAX_TEXTSIZE + 8 )
#define MAX_USERINFO_SIZE	MAX_USERINDEX_SIZE

/* The size of the default buffer used to read data from a keyset.  If
   the data is larger than this, a large buffer is allocated dynamically */

#define KEYSET_BUFFERSIZE	1024

/* The different types of userID which we can use for matching purposes */

typedef enum {
	USERID_NONE,		/* No userID type */
	USERID_USERID,		/* User's userID */
	USERID_CREATORID,	/* Creating SO's userID */
	USERID_NAME,		/* User's name */
	USERID_LAST			/* Last possible userID type */
	} USERID_TYPE;

/* Find a user in the user index.  Note that this search implements a flat
   namespace rather than allowing duplicate names created by different SOs
   because when we're looking up a user we don't know which SO they belong
   to until after we've looked them up */

static int findUser( const void *userIndexData, const int userIndexDataLength,
					 const USERID_TYPE idType, const void *userID,
					 const int userIDlength )
	{
	STREAM stream;
	int fileReference = CRYPT_ERROR_NOTFOUND;
	int iterationCount = 0, status = CRYPT_OK;

	assert( isReadPtr( userIndexData, userIndexDataLength ) );
	assert( ( ( idType > USERID_NONE && idType < USERID_LAST ) && \
			  isReadPtr( userID, userIDlength ) ) || \
			( idType == USERID_NONE && userID == NULL && userIDlength == 0 ) );

	/* Check each entry to make sure that the user name or ID aren't already
	   present */
	sMemConnect( &stream, userIndexData, userIndexDataLength );
	while( stell( &stream ) < userIndexDataLength && \
		   iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
		{
		BYTE userData[ 128 + 8 ];
		long newFileReference;
		int userDataLength;

		readSequence( &stream, NULL );
		if( idType == USERID_USERID )
			readOctetString( &stream, userData, &userDataLength, 
							 KEYID_SIZE, KEYID_SIZE );
		else
			readUniversal( &stream );
		if( idType == USERID_CREATORID )
			readOctetString( &stream, userData, &userDataLength, 
							 KEYID_SIZE, KEYID_SIZE );
		else
			readUniversal( &stream );
		if( idType == USERID_NAME )
			readCharacterString( &stream, userData, &userDataLength,
								 CRYPT_MAX_TEXTSIZE, BER_STRING_UTF8 );
		else
			readUniversal( &stream );
		status = readShortInteger( &stream, &newFileReference );
		if( cryptStatusError( status ) )
			break;
		if( idType == USERID_NONE )
			{
			/* If we're looking for a free file reference and there's one
			   present thats higher then the existing one, remember the new
			   maximum value */
			if( newFileReference > fileReference )
				fileReference = newFileReference;
			}
		else
			/* Check whether this is the user info we want */
			if( userIDlength == userDataLength && \
				!memcmp( userData, userData, userDataLength ) )
				{
				fileReference = ( int ) newFileReference;
				break;
				}
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	sMemDisconnect( &stream );

	return( cryptStatusError( status ) ? status : fileReference );
	}

/* Open a user keyset */

static int openUserKeyset( CRYPT_KEYSET *iUserKeyset, const char *fileName,
						   const int options )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	char userFilePath[ MAX_PATH_LENGTH + 128 ];	/* Protection for Windows */
	int status;

	/* Clear return value */
	*iUserKeyset = CRYPT_ERROR;

	/* Open the given keyset */
	fileBuildCryptlibPath( userFilePath, MAX_PATH_LENGTH, fileName,
						   ( options == CRYPT_KEYOPT_READONLY ) ? \
						   BUILDPATH_GETPATH : BUILDPATH_CREATEPATH );
	setMessageCreateObjectInfo( &createInfo, CRYPT_KEYSET_FILE );
	createInfo.arg2 = options;
	createInfo.strArg1 = userFilePath;
	createInfo.strArgLen1 = strlen( userFilePath );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_KEYSET );
	if( cryptStatusOK( status ) )
		*iUserKeyset = createInfo.cryptHandle;
	return( status );
	}

/* Read data from a user keyset.  This takes a pointer to a buffer and
   optionally allocates a larger buffer if required, with behaviour
   determined by the overallocSize parameter.  If it's less than zero
   then no attempt to allocate a larger buffer is made, if it's zero
   then a larger buffer is allocated, and if it's larger than zero then
   a buffer of the required size plus the overallocSize value is
   allocated */

static int readUserData( const CRYPT_KEYSET iUserKeyset,
						 const CRYPT_ATTRIBUTE_TYPE dataType,
						 void **data, int *dataLength,
						 const int overallocSize )
	{
	MESSAGE_DATA msgData;
	void *dataPtr = *data;
	int status;

	/* Clear return value */
	*dataLength = 0;

	/* Read the requested data from the keyset, allocating a bigger
	   buffer if required.  When we allocate the buffer we add a caller-
	   specified over-allocation amount to handle any extra data the caller
	   wants to add to the buffer */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iUserKeyset, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, dataType );
	if( cryptStatusError( status ) )
		return( status );
	if( msgData.length > KEYSET_BUFFERSIZE )
		{
		if( overallocSize == CRYPT_ERROR )
			/* Don't try to reallocate the buffer if it's too small, there
			   shouldn't be this much data present */
			return( CRYPT_ERROR_OVERFLOW );
		if( ( dataPtr = clDynAlloc( "readUserData", \
									msgData.length + overallocSize ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		}
	msgData.data = dataPtr;
	status = krnlSendMessage( iUserKeyset, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, dataType );
	if( cryptStatusError( status ) )
		{
		if( dataPtr != *data )
			clFree( "readUserData", dataPtr );
		}
	else
		{
		*data = dataPtr;
		*dataLength = msgData.length;
		}
	return( status );
	}

/* Find the file reference for a given user in the index keyset */

static int findUserFileRef( const USERID_TYPE idType, const BYTE *id,
							const int idLength )
	{
	CRYPT_KEYSET iUserKeyset;
	BYTE buffer[ KEYSET_BUFFERSIZE + 8 ];
	void *bufPtr = buffer;
	int length, status;

	/* Open the index file and read the index entries from it */
	status = openUserKeyset( &iUserKeyset, "index", CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		/* If there's no index file present, we're in the zeroised state,
		   the only valid user is the (implicitly present) primary SO */
		if( status == CRYPT_ERROR_NOTFOUND && idType == USERID_NAME && \
			idLength == primarySOInfo.userNameLength && \
			!memcmp( id, primarySOInfo.userName,
					 primarySOInfo.userNameLength ) )
			status = OK_SPECIAL;

		return( status );
		}
	status = readUserData( iUserKeyset, CRYPT_IATTRIBUTE_USERINDEX,
						   &bufPtr, &length, 0 );
	krnlSendNotifier( iUserKeyset, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		if( bufPtr != buffer )
			clFree( "findUserFileRef", bufPtr );
		return( status );
		}

	/* Check whether this user is present in the index */
	status = findUser( bufPtr, length, idType, id, idLength );
	if( bufPtr != buffer )
		clFree( "findUserFileRef", bufPtr );

	return( status );
	}

/* Insert a new entry into the index */

static int insertIndexEntry( const USER_INFO *userInfoPtr,
							 BYTE *userIndexData, int *userIndexDataLength )
	{
	STREAM stream;
	BYTE userInfoBuffer[ MAX_USERINDEX_SIZE + 8 ];
	int userInfoLength, newReference = 0, lastPos = 0;

	/* If there's already index data present, find the appropriate place to
	   insert the new entry and the file reference to use */
	if( *userIndexDataLength > 0 )
		{
		int iterationCount = 0;
		
		sMemConnect( &stream, userIndexData, *userIndexDataLength );
		while( stell( &stream ) < *userIndexDataLength && \
			   iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
			{
			long fileReference;
			int status;

			/* Read an index entry and check whether the file reference
			   matches the expected file reference */
			readSequence( &stream, NULL );
			readUniversal( &stream );
			readUniversal( &stream );
			status = readShortInteger( &stream, &fileReference );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( &stream );
				return( status );
				}
			if( fileReference != newReference )
				break;
			lastPos = stell( &stream );
			newReference++;
			}
		if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
			retIntError();
		sMemDisconnect( &stream );
		}

	/* We've found an unused reference, insert the user data at this point */
	sMemOpen( &stream, userInfoBuffer, MAX_USERINDEX_SIZE );
	writeSequence( &stream, 2 * sizeofObject( KEYID_SIZE ) + \
				   sizeofObject( userInfoPtr->userNameLength ) + \
				   sizeofShortInteger( newReference ) );
	writeOctetString( &stream, userInfoPtr->userID, KEYID_SIZE, DEFAULT_TAG );
	writeOctetString( &stream, userInfoPtr->creatorID, KEYID_SIZE, DEFAULT_TAG );
	writeCharacterString( &stream, userInfoPtr->userName,
						  userInfoPtr->userNameLength, BER_STRING_UTF8 );
	writeShortInteger( &stream, newReference, DEFAULT_TAG );
	userInfoLength = stell( &stream );
	sMemDisconnect( &stream );
	if( lastPos < *userIndexDataLength )
		memmove( userIndexData + lastPos + userInfoLength,
				 userIndexData + lastPos, *userIndexDataLength - lastPos );
	memcpy( userIndexData + lastPos, userInfoBuffer, userInfoLength );
	*userIndexDataLength += userInfoLength;

	return( newReference );
	}

/* Read a user's info from a user keyset and verify it using the creating
   SO's key */

static int getCheckUserInfo( USER_FILE_INFO *userFileInfo, const int fileRef )
	{
	CRYPT_ALGO_TYPE hashAlgo;
	CRYPT_KEYSET iUserKeyset;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	STREAM stream;
	BYTE buffer[ KEYSET_BUFFERSIZE + 8 ];
	void *bufPtr = buffer, *hashDataPtr, *signaturePtr;
	char userFileName[ 16 + 8 ];
	int soFileRef, hashDataLength, signatureLength, length, enumValue, status;

	/* Clear return values */
	memset( userFileInfo, 0, sizeof( USER_FILE_INFO ) );

	/* Open the index keyset and read the user info from it */
	sPrintf_s( userFileName, 16, "u%06x", fileRef );
	status = openUserKeyset( &iUserKeyset, userFileName,
							 CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		return( status );
	status = readUserData( iUserKeyset, CRYPT_IATTRIBUTE_USERINFO,
						   &bufPtr, &length, CRYPT_ERROR );
	krnlSendNotifier( iUserKeyset, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Burrow into the user info to get the information we need.  We do it
	   this way rather than using envelopes because we don't need the full
	   generality of the enveloping process (we know exactly what data to
	   expect) and to avoid the overhead of de-enveloping data every time a
	   user logs in */
	sMemConnect( &stream, buffer, length );
	readSequence( &stream, NULL );			/* Outer wrapper */
	readUniversal( &stream );				/* ContentType OID */
	readConstructed( &stream, NULL, 0 );	/* Content */
	readSequence( &stream, NULL );
	readUniversal( &stream );				/* Version */
	readSet( &stream, NULL );				/* DigestAlgorithms */
	readAlgoID( &stream, &hashAlgo );
	readSequence( &stream, NULL );			/* EncapContentInfo */
	readUniversal( &stream );				/* ContentType OID */
	readConstructed( &stream, NULL, 0 );	/* Content type wrapper */
	status = readGenericHole( &stream, &hashDataLength, 16, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	hashDataPtr = sMemBufPtr( &stream );

	/* Read the user info */
	readSequence( &stream, NULL );
	readEnumerated( &stream, &enumValue );
	userFileInfo->type = enumValue;
	readOctetString( &stream, userFileInfo->userID, &length, 
					 KEYID_SIZE, KEYID_SIZE );
	readOctetString( &stream, userFileInfo->creatorID, &length, 
					 KEYID_SIZE, KEYID_SIZE );
	status = readCharacterString( &stream, userFileInfo->userName,
								  &userFileInfo->userNameLength,
								  CRYPT_MAX_TEXTSIZE, BER_STRING_UTF8 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Read the signature */
	status = readSet( &stream, &signatureLength );
	signaturePtr = sMemBufPtr( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Open the SO keyset and read the SO public key from it */
	status = soFileRef = \
		findUserFileRef( USERID_USERID, userFileInfo->creatorID, KEYID_SIZE );
	if( cryptStatusOK( status ) )
		{
		sPrintf_s( userFileName, 16, "u%06x", soFileRef );
		status = openUserKeyset( &iUserKeyset, userFileName,
								 CRYPT_KEYOPT_READONLY );
		}
	if( cryptStatusError( status ) )
		return( status );
	setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_KEYID,
						   userFileInfo->creatorID, KEYID_SIZE, NULL, 0,
						   KEYMGMT_FLAG_NONE );
	status = krnlSendMessage( iUserKeyset, IMESSAGE_KEY_GETKEY,
							  &getkeyInfo, KEYMGMT_ITEM_PUBLICKEY );
	krnlSendNotifier( iUserKeyset, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Hash the signed data and verify the signature using the SO key */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
						 hashDataPtr, hashDataLength );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_CTX_HASH, hashDataPtr, 0 );
		if( cryptStatusOK( status ) )
			status = iCryptCheckSignatureEx( signaturePtr, signatureLength,
											 CRYPT_FORMAT_CRYPTLIB,
											 getkeyInfo.cryptHandle,
											 createInfo.cryptHandle, NULL );
		krnlSendNotifier( createInfo.cryptHandle,
						  IMESSAGE_DECREFCOUNT );
		}
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
	/* MAC (???) using password - needs PKCS #15 changes */
	/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

	if( cryptStatusError( status ) )
		return( status );

	return( status );
	}

/* Create an SO private key and write it to the user keyset */

static int createSOKey( const CRYPT_KEYSET iUserKeyset,
						USER_INFO *userInfoPtr, const char *password,
						const int passwordLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int keyLength = /*128*/64;
	const int actionPerms = MK_ACTION_PERM( MESSAGE_CTX_SIGN,
											ACTION_PERM_NONE_EXTERNAL ) | \
							MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK,
											ACTION_PERM_NONE_EXTERNAL );
	int status;

#if !defined( NDEBUG ) && !defined( __WIN16__ )
/* Warn that we're using a debug mode for now.  The user management code
   isn't complete yet so this isn't a problem */
puts( "Kludging SO key size to 512 bits." );
#endif /* Systems with stdio */

	/* Create the SO private key, making it internal and signature-only */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_RSA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, userInfoPtr->userName,
					min( userInfoPtr->userNameLength, CRYPT_MAX_TEXTSIZE ) );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_LABEL );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( int * ) &keyLength, CRYPT_CTXINFO_KEYSIZE );
	status = krnlSendMessage( createInfo.cryptHandle,
							  IMESSAGE_CTX_GENKEY, NULL, FALSE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE,
								  ( int * ) &actionPerms,
								  CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Add the newly-created private key to the keyset */
	setMessageData( &msgData, ( void * ) userInfoPtr->userID, KEYID_SIZE );
	status = krnlSendMessage( iUserKeyset, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_USERID );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_KEYMGMT_INFO setkeyInfo;

		setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
							   ( void * ) password, passwordLength,
							   KEYMGMT_FLAG_NONE );
		setkeyInfo.cryptHandle = createInfo.cryptHandle;
		status = krnlSendMessage( iUserKeyset, IMESSAGE_KEY_SETKEY,
								  &setkeyInfo, KEYMGMT_ITEM_PRIVATEKEY );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	userInfoPtr->iCryptContext = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

#if 0	/* Currently unused, for future use for CA users */

/* Create a CA secret key and write it to the user keyset */

static int createCAKey( const CRYPT_KEYSET iUserKeyset,
						USER_INFO *userInfoPtr, const char *password,
						const int passwordLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int actionPerms = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT,
											ACTION_PERM_NONE_EXTERNAL ) | \
							MK_ACTION_PERM( MESSAGE_CTX_DECRYPT,
											ACTION_PERM_NONE_EXTERNAL );
	int status;

	/* Create the CA secret key, making it internal-only */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_3DES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, userInfoPtr->userID, KEYID_SIZE );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_LABEL );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_GENKEY,
							  NULL, FALSE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE,
								  ( int * ) &actionPerms,
								  CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Add the newly-created secret key to the keyset */
	setMessageData( &msgData, ( void * ) userInfoPtr->userID, KEYID_SIZE );
	status = krnlSendMessage( iUserKeyset, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_USERID );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_KEYMGMT_INFO setkeyInfo;

		setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
							   ( void * ) password, passwordLength,
							   KEYMGMT_FLAG_NONE );
		setkeyInfo.cryptHandle = createInfo.cryptHandle;
		status = krnlSendMessage( iUserKeyset, IMESSAGE_KEY_SETKEY,
								  &setkeyInfo, KEYMGMT_ITEM_SECRETKEY );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	return( CRYPT_OK );
	}
#endif /* 0 */

/* Sign the user info and write it to the user keyset */

static int writeUserInfo( const CRYPT_KEYSET iUserKeyset,
						  const USER_INFO *userInfoPtr,
						  const CRYPT_CONTEXT iSignContext )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE userInfoBuffer[ 1024 + 8 ];
	static const int minBufferSize = MIN_BUFFER_SIZE;
	int userInfoLength, status;

	/* The user info buffer is used to hold both the user info data and
	   the enveloped content of the data, so we make sure that there's
	   plenty of room to contain the enveloped data */
	assert( MAX_USERINFO_SIZE < 1024 - 256 );

	/* Write the user information to a memory buffer */
	sMemOpen( &stream, userInfoBuffer, MAX_USERINFO_SIZE );
	writeSequence( &stream, sizeofShortInteger( userInfoPtr->type ) + \
				   2 * sizeofObject( KEYID_SIZE ) + \
				   sizeofObject( userInfoPtr->userNameLength ) );
	writeEnumerated( &stream, userInfoPtr->type, DEFAULT_TAG );
	writeOctetString( &stream, userInfoPtr->userID, KEYID_SIZE, DEFAULT_TAG );
	writeOctetString( &stream, userInfoPtr->creatorID, KEYID_SIZE, DEFAULT_TAG );
	writeCharacterString( &stream, userInfoPtr->userName,
						  userInfoPtr->userNameLength, BER_STRING_UTF8 );
	userInfoLength = stell( &stream );
	sMemDisconnect( &stream );

	/* Create a cryptlib envelope to sign the data.  This is kind of
	   heavyweight, but it's OK because we rarely create new users and it
	   saves having to hand-assemble the data like the PKCS #15 code does */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_CRYPTLIB );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( int * ) &minBufferSize, CRYPT_ATTRIBUTE_BUFFERSIZE );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 &userInfoLength, CRYPT_ENVINFO_DATASIZE );
	status = krnlSendMessage( createInfo.cryptHandle,
							  IMESSAGE_SETATTRIBUTE,
							  ( void * ) &iSignContext,
							  CRYPT_ENVINFO_SIGNATURE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Push in the data and pop the signed result */
	setMessageData( &msgData, userInfoBuffer, userInfoLength );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_ENV_PUSHDATA,
							  &msgData, 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, userInfoBuffer, 1024 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_ENV_POPDATA, &msgData, 0 );
		}
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the user ID and SO-signed user info to the keyset */
	status = krnlSendMessage( iUserKeyset, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_USERINFO );
	zeroise( userInfoBuffer, 1024 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( void * ) userInfoPtr->userID,
						KEYID_SIZE );
		status = krnlSendMessage( iUserKeyset, IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_USERID );
		}
	return( status );
	}

/****************************************************************************
*																			*
*							User Management Functions						*
*																			*
****************************************************************************/

/* Perform a zeroise */

static int zeroiseUsers( void )
	{
	CRYPT_KEYSET iIndexKeyset;
	MESSAGE_DATA msgData;
	STREAM stream;
	static const BYTE zeroUserData[] = { 0x30, 0x00 };
	BYTE buffer[ KEYSET_BUFFERSIZE + 8 ];
	void *bufPtr = buffer;
	int length, iterationCount = 0, status;

	/* Open the index file and read the index entries from it.  We open it in
	   exclusive mode and keep it open to ensure that noone else can access
	   it while the zeroise is occurring */
	status = openUserKeyset( &iIndexKeyset, "index",
							 CRYPT_IKEYOPT_EXCLUSIVEACCESS );
	if( cryptStatusError( status ) )
		{
		/* If there's no index file present, we're already in the zeroised
		   state */
		if( status == CRYPT_ERROR_NOTFOUND )
			return( CRYPT_OK );

		/* If there's something there but it's damaged, delete it so we can
		   start again */
		if( status == CRYPT_ERROR_BADDATA )
			{
			char userFilePath[ MAX_PATH_LENGTH + 128 ];	/* Protection for Windows */

			fileBuildCryptlibPath( userFilePath, MAX_PATH_LENGTH, "index",
								   BUILDPATH_GETPATH );
			fileErase( userFilePath );

			return( CRYPT_OK );
			}

		return( status );
		}
	status = readUserData( iIndexKeyset, CRYPT_IATTRIBUTE_USERINDEX,
						   &bufPtr, &length, 0 );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iIndexKeyset, IMESSAGE_DECREFCOUNT );
		if( bufPtr != buffer )
			clFree( "zeroiseUsers", bufPtr );
		return( status );
		}

	/* Step through each entry clearing the user info for it */
	sMemConnect( &stream, bufPtr, length );
	while( stell( &stream ) < length && \
		   iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
		{
		STREAM fileStream;
		char userFilePath[ MAX_PATH_LENGTH + 128 ];	/* Protection for Windows */
		char userFileName[ 16 + 8 ];
		long fileRef;

		/* Get the file reference for this user */
		readSequence( &stream, NULL );
		readUniversal( &stream );
		readUniversal( &stream );
		readUniversal( &stream );
		status = readShortInteger( &stream, &fileRef );
		if( cryptStatusError( status ) )
			continue;

		/* Erase the given user keyset */
		sPrintf_s( userFileName, 16, "u%06lx",  fileRef );
		fileBuildCryptlibPath( userFilePath, MAX_PATH_LENGTH, userFileName,
							   BUILDPATH_GETPATH );
		status = sFileOpen( &fileStream, userFilePath,
							FILE_READ | FILE_WRITE | FILE_EXCLUSIVE_ACCESS );
		if( cryptStatusError( status ) )
			continue;
		fileClearToEOF( &fileStream );
		sFileClose( &fileStream );
		fileErase( userFilePath );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	sMemDisconnect( &stream );
	if( bufPtr != buffer )
		clFree( "zeroiseUsers", bufPtr );

	/* Erase the index file by setting zero-length user index info, which
	   results in an empty keyset which is erased on close */
	setMessageData( &msgData, ( void * ) zeroUserData, 2 );
	status = krnlSendMessage( iIndexKeyset, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_USERINDEX );
	krnlSendNotifier( iIndexKeyset, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Create a user object keyset */

static int createUserKeyset( CRYPT_KEYSET *iCreatedKeyset,
							 USER_INFO *userInfoPtr )
	{
	CRYPT_KEYSET iIndexKeyset, iUserKeyset;
	BOOLEAN newIndex = FALSE;
	BYTE buffer[ KEYSET_BUFFERSIZE + 8 ];
	void *bufPtr = buffer;
	char userFileName[ 16 + 8 ];
	int fileRef, length, status;

	/* Clear return value */
	*iCreatedKeyset = CRYPT_ERROR;

	/* Try and open the config file.  If we can't open it and the return
	   status indicates that the file doesn't exist, try and create it
	   instead */
	status = openUserKeyset( &iIndexKeyset, "index",
							 CRYPT_IKEYOPT_EXCLUSIVEACCESS );
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		status = openUserKeyset( &iIndexKeyset, "index",
								 CRYPT_KEYOPT_CREATE );
		newIndex = TRUE;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If there's index data present, read it and make sure that the new
	   user isn't already present */
	if( !newIndex )
		{
		int iterationCount = 0;
		
		/* Read the index entries from the keyset */
		status = readUserData( iIndexKeyset, CRYPT_IATTRIBUTE_USERINDEX,
							   &bufPtr, &length, MAX_USERINDEX_SIZE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iIndexKeyset, IMESSAGE_DECREFCOUNT );
			if( bufPtr != buffer )
				clFree( "createUserKeyset", bufPtr );
			return( status );
			}

		/* Check whether this user is present in the index */
		status = findUser( bufPtr, length, USERID_NAME, userInfoPtr->userName,
						   userInfoPtr->userNameLength );
		if( !cryptStatusError( status ) )
			{
			krnlSendNotifier( iIndexKeyset, IMESSAGE_DECREFCOUNT );
			if( bufPtr != buffer )
				clFree( "createUserKeyset", bufPtr );
			return( CRYPT_ERROR_DUPLICATE );
			}

		/* Make sure that the userID is unique */
		do
			{
			status = findUser( bufPtr, length, USERID_USERID,
							   userInfoPtr->userID, KEYID_SIZE );
			if( !cryptStatusError( status ) )
				{
				MESSAGE_DATA msgData;

				setMessageData( &msgData, userInfoPtr->userID, KEYID_SIZE );
				status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
										  IMESSAGE_GETATTRIBUTE_S, &msgData,
										  CRYPT_IATTRIBUTE_RANDOM_NONCE );
				}
			}
		while( !cryptStatusError( status ) && \
			   iterationCount++ < FAILSAFE_ITERATIONS_LARGE );
		if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
			retIntError();

		/* Locate a new unused file reference that we can use */
		fileRef = findUser( bufPtr, length, USERID_NONE, NULL, 0 );
		}
	else
		/* No users present yet, use the first user entry */
		fileRef = length = 0;

	/* Create the user keyset */
	sPrintf_s( userFileName, 16, "u%06x", fileRef );
	status = openUserKeyset( &iUserKeyset, userFileName,
							 CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iIndexKeyset, IMESSAGE_DECREFCOUNT );
		if( bufPtr != buffer )
			clFree( "createUserKeyset", bufPtr );
		return( status );
		}

	/* Update the index file */
	status = insertIndexEntry( userInfoPtr, bufPtr, &length );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, bufPtr, length );
		status = krnlSendMessage( iIndexKeyset, IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_USERINDEX );
		}
	if( cryptStatusError( status ) )
		/* We couldn't update the index file, delete the newly-created user
		   keyset (since we haven't written anything to it, it's zero-length
		   so it's deleted automatically on close) */
		krnlSendNotifier( iUserKeyset, IMESSAGE_DECREFCOUNT );
	else
		{
		userInfoPtr->fileRef = fileRef;
		*iCreatedKeyset = iUserKeyset;
		}
	krnlSendNotifier( iIndexKeyset, IMESSAGE_DECREFCOUNT );

	/* Clean up */
	if( bufPtr != buffer )
		clFree( "createUserKeyset", bufPtr );
	return( status );
	}

/* Set/change the password for a user object */

static int setPassword( USER_INFO *userInfoPtr, const char *password,
						const int passwordLength )
	{
	CRYPT_KEYSET iUserKeyset;
	int status;

	/* No-one can ever directly set the default SO password */
	if( passwordLength == PRIMARYSO_PASSWORD_LENGTH && \
		( !memcmp( password, PRIMARYSO_PASSWORD,
				   PRIMARYSO_PASSWORD_LENGTH ) || \
		  !memcmp( password, PRIMARYSO_ALTPASSWORD,
				   PRIMARYSO_PASSWORD_LENGTH ) ) )
		return( CRYPT_ERROR_WRONGKEY );

	/* If we're setting the password for the primary SO in the zeroised
	   state, create a new user keyset and SO authentication key and write
	   the details to the keyset */
	if( userInfoPtr->fileRef == -1 )
		{
		status = createUserKeyset( &iUserKeyset, userInfoPtr );
		assert( ( cryptStatusError( status ) && userInfoPtr->fileRef == -1 ) || \
				( cryptStatusOK( status ) && userInfoPtr->fileRef == 0 ) );
		if( cryptStatusOK( status ) )
			{
			MESSAGE_DATA msgData;

			/* Since this user is created implicitly, there's no userID set
			   by an explicit create so we set it now.  Since this is
			   effectively a self-created user we also set the creatorID to
			   the userID */
			setMessageData( &msgData, userInfoPtr->userID, KEYID_SIZE );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			if( cryptStatusOK( status ) )
				{
				memcpy( userInfoPtr->creatorID, userInfoPtr->userID,
						KEYID_SIZE );
				status = createSOKey( iUserKeyset, userInfoPtr,
									  password, passwordLength );
				}
			}
		if( cryptStatusOK( status ) )
			status = writeUserInfo( iUserKeyset, userInfoPtr,
									userInfoPtr->iCryptContext );

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*status = createCAKey( iUserKeyset, userInfoPtr, password, passwordLength );*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
		}
	else
		{
		char userFileName[ 16 + 8 ];

		/* Open an existing user keyset */
		sPrintf_s( userFileName, 16, "u%06x", userInfoPtr->fileRef );
		status = openUserKeyset( &iUserKeyset, userFileName,
								 CRYPT_KEYOPT_NONE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
	/* set state = USER_INITED */
	/* write MAC( ??? ) to user file - needs PKCS #15 changes */
	/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

	/* Close the keyset and commit the changes */
	krnlSendNotifier( iUserKeyset, IMESSAGE_DECREFCOUNT );

	/* The password has been set, we're now in the user inited state */
	userInfoPtr->state = USER_STATE_USERINITED;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							General User Object Functions					*
*																			*
****************************************************************************/

/* Handle a message sent to a user object */

static int userMessageFunction( const void *objectInfoPtr,
								const MESSAGE_TYPE message,
								void *messageDataPtr, const int messageValue )
	{
	USER_INFO *userInfoPtr = ( USER_INFO * ) objectInfoPtr;

	/* Process destroy object messages */
	if( message == MESSAGE_DESTROY )
		{
		/* Clean up any user-related crypto objects if necessary */
		if( userInfoPtr->iCryptContext != CRYPT_ERROR )
			krnlSendNotifier( userInfoPtr->iCryptContext,
							  IMESSAGE_DECREFCOUNT );
		if( userInfoPtr->iKeyset != CRYPT_ERROR )
			krnlSendNotifier( userInfoPtr->iKeyset, IMESSAGE_DECREFCOUNT );

		/* Clean up the trust info and config options */
		endTrustInfo( userInfoPtr->trustInfoPtr );
		endOptions( userInfoPtr->configOptions );

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		const CRYPT_USER iCryptUser = userInfoPtr->objectHandle;
		char userFileName[ 16 + 8 ];
		void *data;
		int length, refCount, status;

		if( messageValue == CRYPT_USERINFO_PASSWORD )
			{
			MESSAGE_DATA *msgData = messageDataPtr;

			return( setPassword( userInfoPtr, msgData->data,
								 msgData->length ) );
			}
		if( messageValue == CRYPT_USERINFO_CAKEY_CERTSIGN || \
			messageValue == CRYPT_USERINFO_CAKEY_CRLSIGN || \
			messageValue == CRYPT_USERINFO_CAKEY_OCSPSIGN )
			{
			const int objectHandle = *( int * ) messageDataPtr;
			const int requiredKeyUsage = \
				( messageValue == CRYPT_USERINFO_CAKEY_CERTSIGN ) ? \
					CRYPT_KEYUSAGE_KEYCERTSIGN : \
				( messageValue == CRYPT_USERINFO_CAKEY_CRLSIGN ) ? \
					CRYPT_KEYUSAGE_CRLSIGN : \
					( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
					  CRYPT_KEYUSAGE_NONREPUDIATION );
			int value;

			/* Make sure that we've been given a signing key */
			status = krnlSendMessage( objectHandle, IMESSAGE_CHECK,
									  NULL, MESSAGE_CHECK_PKC_SIGN );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_NUM1 );

			/* Make sure that the object has an initialised cert of the
			   correct type associated with it */
			status = krnlSendMessage( objectHandle, IMESSAGE_GETATTRIBUTE,
									  &value, CRYPT_CERTINFO_IMMUTABLE );
			if( cryptStatusError( status ) || !value )
				return( CRYPT_ARGERROR_NUM1 );
			status = krnlSendMessage( objectHandle, IMESSAGE_GETATTRIBUTE,
									  &value, CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) ||
				( value != CRYPT_CERTTYPE_CERTIFICATE && \
				  value != CRYPT_CERTTYPE_CERTCHAIN ) )
				return( CRYPT_ARGERROR_NUM1 );

			/* Make sure that the key usage required for this action is
			   permitted.  OCSP is a bit difficult since the key may or may
			   not have an OCSP extended usage (depending on whether the CA
			   bothers to set it or not, even if they do they may delegate
			   the functionality to a short-term generic signing key) and the
			   signing ability may be indicated by either a digital signature
			   flag or a nonrepudiation flag depending on whether the CA
			   considers an OCSP signature to be short or long-term, so we
			   just check for a generic signing ability */
			status = krnlSendMessage( objectHandle, IMESSAGE_GETATTRIBUTE,
									  &value, CRYPT_CERTINFO_KEYUSAGE );
			if( cryptStatusError( status ) || !( value & requiredKeyUsage ) )
				return( CRYPT_ARGERROR_NUM1 );

			/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
			/* Save this in the keyset at some point */
			/* Handle get (gets public key) */
			/* Handle delete (removes key) */
			/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

			return( status );
			}
		if( messageValue == CRYPT_IATTRUBUTE_CERTKEYSET )
			{
			int iCryptKeyset = *( ( int * ) messageDataPtr );

			assert( message == MESSAGE_SETATTRIBUTE );

			/* If it's a presence check, handle it specially */
			if( iCryptKeyset == CRYPT_UNUSED )
				return( enumTrustedCerts( userInfoPtr->trustInfoPtr,
										  CRYPT_UNUSED, CRYPT_UNUSED ) );

			/* Send all trusted certs to the keyset */
			return( enumTrustedCerts( userInfoPtr->trustInfoPtr,
									  CRYPT_UNUSED, iCryptKeyset ) );
			}
		if( messageValue == CRYPT_IATTRIBUTE_CTL )
			{
			MESSAGE_CREATEOBJECT_INFO createInfo;
			int *iCryptCtlPtr = ( int * ) messageDataPtr;

			assert( message == MESSAGE_GETATTRIBUTE || \
					message == MESSAGE_SETATTRIBUTE );

			/* If we're setting trust info, add the certs via the trust
			   list */
			if( message == MESSAGE_SETATTRIBUTE )
				{
				status = addTrustEntry( userInfoPtr->trustInfoPtr,
										*iCryptCtlPtr, NULL, 0, FALSE );
				if( cryptStatusOK( status ) )
					userInfoPtr->trustInfoChanged = TRUE;
				return( status );
				}

			/* Clear return value */
			*iCryptCtlPtr = CRYPT_ERROR;

			status = enumTrustedCerts( userInfoPtr->trustInfoPtr,
									   CRYPT_UNUSED, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				return( status );

			/* Create a cert chain meta-object to hold the overall set of
			   certs */
			setMessageCreateObjectInfo( &createInfo,
										CRYPT_CERTTYPE_CERTCHAIN );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_DEV_CREATEOBJECT,
									  &createInfo, OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );

			status = enumTrustedCerts( userInfoPtr->trustInfoPtr,
									   createInfo.cryptHandle, CRYPT_UNUSED );
			if( cryptStatusOK( status ) )
				*iCryptCtlPtr = createInfo.cryptHandle;
			else
				krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		if( messageValue == CRYPT_IATTRIBUTE_CERT_TRUSTED )
			{
			const CRYPT_CERTIFICATE cryptCert = \
								*( ( CRYPT_CERTIFICATE * ) messageDataPtr );

			assert( message == MESSAGE_SETATTRIBUTE );

			/* Add the cert to the trust info */
			status = addTrustEntry( userInfoPtr->trustInfoPtr, cryptCert,
									NULL, 0, TRUE );
			if( cryptStatusOK( status ) )
				{
				userInfoPtr->trustInfoChanged = TRUE;
				setOption( userInfoPtr->configOptions,
						   CRYPT_OPTION_CONFIGCHANGED, TRUE );
				}
			return( status );
			}
		if( messageValue == CRYPT_IATTRIBUTE_CERT_UNTRUSTED )
			{
			const CRYPT_CERTIFICATE cryptCert = \
								*( ( CRYPT_CERTIFICATE * ) messageDataPtr );
			void *entryToDelete;

			assert( message == MESSAGE_SETATTRIBUTE );

			/* Find the entry to delete and remove it */
			if( ( entryToDelete = findTrustEntry( userInfoPtr->trustInfoPtr,
												  cryptCert, FALSE ) ) == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			deleteTrustEntry( userInfoPtr->trustInfoPtr, entryToDelete );
			userInfoPtr->trustInfoChanged = TRUE;
			setOption( userInfoPtr->configOptions,
					   CRYPT_OPTION_CONFIGCHANGED, TRUE );
			return( CRYPT_OK );
			}
		if( messageValue == CRYPT_IATTRIBUTE_CERT_CHECKTRUST )
			{
			const CRYPT_CERTIFICATE cryptCert = \
								*( ( CRYPT_CERTIFICATE * ) messageDataPtr );
			int certType;

			assert( message == MESSAGE_SETATTRIBUTE );

			/* We can't perform this action as a MESSAGE_CHECK because these
			   are sent to the object being checked (the certificate in this
			   case) rather than the user object it's associated with, so we
			   have to do it as a pseudo-attribute-set action */
			status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE,
									  &certType, CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) || \
				( certType != CRYPT_CERTTYPE_CERTIFICATE && \
				  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
				/* A non-cert can never be implicitly trusted */
				return( FALSE );

			/* Check whether the cert is present in the trusted certs
			   collection */
			return( ( findTrustEntry( userInfoPtr->trustInfoPtr, cryptCert,
									  FALSE ) != NULL ) ? \
					CRYPT_OK : CRYPT_ERROR_INVALID );
			}
		if( messageValue == CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER )
			{
			const CRYPT_CERTIFICATE cryptCert = \
								*( ( CRYPT_CERTIFICATE * ) messageDataPtr );
			void *trustedIssuerInfo;

			assert( message == MESSAGE_SETATTRIBUTE );

			/* This is a highly nonstandard use of integer parameters that
			   passes in the user cert as its parameter and returns the
			   issuer cert in the same parameter, overwriting the user
			   cert value.  This is the sole message that does this,
			   unfortunately there's no clean way to handle this without
			   implementing a new message type for this purpose.  Since the
			   kernel is stateless it can only look at the parameter value
			   but not detect that it's changed during the call, so it works
			   for now, but it would be nicer to find some way to fix this */
			trustedIssuerInfo = findTrustEntry( userInfoPtr->trustInfoPtr,
												cryptCert, TRUE );
			if( trustedIssuerInfo != NULL )
				{
				const int trustedCert = getTrustedCert( trustedIssuerInfo );
				if( cryptStatusError( trustedCert ) )
					return( trustedCert );
				assert( trustedCert != cryptCert );
				*( ( int * ) messageDataPtr ) = trustedCert;
				return( CRYPT_OK );
				}

			return( CRYPT_ERROR_NOTFOUND );
			}

		if( messageValue == CRYPT_IATTRIBUTE_INITIALISED )
			{
			/* If it's an initialisation message, there's nothing to do (we
			   get these when creating the default user object, which doesn't
			   require an explicit logon to move it into the high state) */
			assert( userInfoPtr->objectHandle == DEFAULTUSER_OBJECT_HANDLE );
			return( CRYPT_OK );
			}

		/* Anything else has to be a config option */
		assert( messageValue > CRYPT_OPTION_FIRST && \
				messageValue < CRYPT_OPTION_LAST );

		/* Delete attribute */
		if( message == MESSAGE_DELETEATTRIBUTE )
			/* Only string attributes can be deleted, so we can safely pass
			   all calls through to the set-string function */
			return( setOptionString( userInfoPtr->configOptions,
									 messageValue, NULL, 0 ) );

		/* Get/set string attributes */
		if( message == MESSAGE_GETATTRIBUTE_S )
			{
			MESSAGE_DATA *msgData = messageDataPtr;
			const char *retVal = getOptionString( userInfoPtr->configOptions,
												  messageValue );
			if( retVal == NULL )
				{
				/* No value set, clear the return value in case the caller
				   isn't checking the return code */
				if( msgData->data != NULL )
					*( ( char * ) msgData->data ) = '\0';
				msgData->length = 0;
				return( CRYPT_ERROR_NOTFOUND );
				}
			return( attributeCopy( msgData, retVal, strlen( retVal ) ) );
			}
		if( message == MESSAGE_SETATTRIBUTE_S )
			{
			const MESSAGE_DATA *msgData = messageDataPtr;

			return( setOptionString( userInfoPtr->configOptions,
									 messageValue, msgData->data,
									 msgData->length ) );
			}

		/* Get/set numeric attributes */
		if( message == MESSAGE_GETATTRIBUTE )
			{
			/* Numeric get can never fail */
			*( ( int * ) messageDataPtr ) = \
							getOption( userInfoPtr->configOptions,
									   messageValue );
			return( CRYPT_OK );
			}
		status = setOption( userInfoPtr->configOptions, messageValue,
							*( ( int * ) messageDataPtr ) );
		if( !( status == OK_SPECIAL && \
			 ( messageValue == CRYPT_OPTION_CONFIGCHANGED || \
			   messageValue == CRYPT_OPTION_SELFTESTOK ) ) )
			return( status );

		/* The following options control operations which are performed
		   in two phases.  The reason for the split is that the second phase
		   doesn't require the use of the user object data any more and can
		   be a somewhat lengthy process due to disk accesses or lengthy
		   crypto operations.  Because of this we unlock the user object
		   between the two phases to ensure that the second phase doesn't
		   stall all other operations which require this user object */
		assert( status == OK_SPECIAL );

		/* If it's a self-test, forward the message to the system object with
		   the user object unlocked, then re-lock it and set the self-test
		   result value.  Since the self-test value will be in the busy state
		   at this point, we need to update it by setting the
		   CRYPT_OPTION_LAST pseudo-option */
		if( messageValue == CRYPT_OPTION_SELFTESTOK )
			{
			int selfTestStatus;

			krnlSuspendObject( iCryptUser, &refCount );
			selfTestStatus = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									IMESSAGE_SETATTRIBUTE, messageDataPtr,
									CRYPT_IATTRIBUTE_SELFTEST );
			status = krnlResumeObject( iCryptUser, refCount );
			if( cryptStatusError( status ) )
				return( status );
			return( setOption( userInfoPtr->configOptions, CRYPT_OPTION_LAST,
							   cryptStatusOK( selfTestStatus ) ? \
							   *( ( int * ) messageDataPtr ) : 0 ) );
			}

		/* The config option write is performed in two phases, a first phase
		   which encodes the config data and a second phase which writes the
		   data to disk */
		assert( messageValue == CRYPT_OPTION_CONFIGCHANGED );
		if( userInfoPtr->fileRef == CRYPT_UNUSED )
			strcpy( userFileName, "cryptlib" );
		else
			sPrintf_s( userFileName, 16, "u%06x", userInfoPtr->fileRef );
		status = encodeConfigData( userInfoPtr->configOptions,
								   userFileName, userInfoPtr->trustInfoPtr,
								   &data, &length );
		if( status != OK_SPECIAL )
			return( status );
		if( length <= 0 && !userInfoPtr->trustInfoChanged )
			return( CRYPT_OK );

		/* We've got the config data in a memory buffer, we can unlock the
		   user object to allow external access while we commit the in-memory
		   data to disk */
		krnlSuspendObject( iCryptUser, &refCount );
		status = commitConfigData( iCryptUser, userFileName, data, length );
		if( cryptStatusOK( status ) )
			userInfoPtr->trustInfoChanged = FALSE;
		clFree( "userMessageFunction", data );
		krnlResumeObject( iCryptUser, refCount );
		return( status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Open a user object.  This is a low-level function encapsulated by
   createUser() and used to manage error exits */

static int openUser( CRYPT_USER *iCryptUser, const CRYPT_USER cryptOwner,
					 const USER_FILE_INFO *userFileInfo,
					 USER_INFO **userInfoPtrPtr )
	{
	USER_INFO *userInfoPtr;
	const OBJECT_SUBTYPE subType = \
		( userFileInfo->type == CRYPT_USER_SO ) ? SUBTYPE_USER_SO : \
		( userFileInfo->type == CRYPT_USER_CA ) ? SUBTYPE_USER_CA : \
		SUBTYPE_USER_NORMAL;
	int status;

	/* The default user is a special type which has both normal user and SO
	   privileges.  This is because in its usual usage mode where cryptlib is
	   functioning as a single-user system the user doesn't know about the
	   existence of user objects and just wants everything to work the way
	   they expect.  Because of this, the default user has to be able to
	   perform the full range of available operations, requiring that they
	   appear as both a normal user and an SO */
#if 0	/* Disabled since ACL checks are messed up by dual-user, 18/5/02 */
	assert( userFileInfo->type == CRYPT_USER_NORMAL || \
			userFileInfo->type == CRYPT_USER_SO || \
			userFileInfo->type == CRYPT_USER_CA || \
			( userFileInfo->type == CRYPT_USER_NONE && \
			  userFileInfo->userNameLength == \
								defaultUserInfo.userNameLength && \
			  !memcmp( userFileInfo->userName, defaultUserInfo.userName,
					   defaultUserInfo.userNameLength ) ) );
#else
	assert( userFileInfo->type == CRYPT_USER_NORMAL || \
			userFileInfo->type == CRYPT_USER_SO || \
			userFileInfo->type == CRYPT_USER_CA );
#endif /* 0 */

	/* Clear the return values */
	*iCryptUser = CRYPT_ERROR;
	*userInfoPtrPtr = NULL;

	/* Create the user object */
	status = krnlCreateObject( ( void ** ) &userInfoPtr, sizeof( USER_INFO ),
							   OBJECT_TYPE_USER, subType,
							   CREATEOBJECT_FLAG_NONE, cryptOwner,
							   ACTION_PERM_NONE_ALL, userMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*userInfoPtrPtr = userInfoPtr;
	*iCryptUser = userInfoPtr->objectHandle = status;
	userInfoPtr->type = userFileInfo->type;
	userInfoPtr->state = userFileInfo->state;
	userInfoPtr->fileRef = userFileInfo->fileRef;
	memcpy( userInfoPtr->userName, userFileInfo->userName,
			userFileInfo->userNameLength );
	userInfoPtr->userNameLength = userFileInfo->userNameLength;
	memcpy( userInfoPtr->userID, userFileInfo->userID, KEYID_SIZE );
	memcpy( userInfoPtr->creatorID, userFileInfo->creatorID, KEYID_SIZE );

	/* Set up any internal objects to contain invalid handles */
	userInfoPtr->iKeyset = userInfoPtr->iCryptContext = CRYPT_ERROR;

	/* Initialise the default user config options */
	status = initTrustInfo( &userInfoPtr->trustInfoPtr );
	if( cryptStatusOK( status ) )
		status = initOptions( &userInfoPtr->configOptions );
	return( status );
	}

int createUser( MESSAGE_CREATEOBJECT_INFO *createInfo,
				const void *auxDataPtr, const int auxValue )
	{
	CRYPT_USER iCryptUser;
	USER_INFO *userInfoPtr;
	char userFileName[ 16 + 8 ];
	int fileRef, initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( createInfo->strArgLen1 < MIN_NAME_LENGTH || \
		createInfo->strArgLen1 > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ARGERROR_STR1 );
	if( createInfo->strArgLen2 < MIN_NAME_LENGTH || \
		createInfo->strArgLen2 > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ARGERROR_STR2 );

	/* We can't create another user object with the same name as the
	   cryptlib default user (actually we could and nothing bad would happen,
	   but we reserve the use of this name just in case) */
	if( createInfo->strArgLen1 == defaultUserInfo.userNameLength && \
		!strCompare( createInfo->strArg1, defaultUserInfo.userName,
					 defaultUserInfo.userNameLength ) )
		return( CRYPT_ERROR_INITED );

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/* Logging on with the primary SO default password triggers a zeroise,
   normally we can only use this login after a zeroise but currently there's
   no way for a user to trigger this so we perform it at the same time as
   the login - the effect is the same, it just combines two operations in
   one */
if( createInfo->strArgLen2 == PRIMARYSO_PASSWORD_LENGTH && \
	( !memcmp( createInfo->strArg2, PRIMARYSO_PASSWORD,
			   PRIMARYSO_PASSWORD_LENGTH ) || \
	  !memcmp( createInfo->strArg2, PRIMARYSO_ALTPASSWORD,
			   PRIMARYSO_PASSWORD_LENGTH ) ) )
	{
	status = zeroiseUsers();
	if( cryptStatusError( status ) )
		return( status );
	}
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

	/* Find the user information for the given user */
	status = fileRef = findUserFileRef( USERID_NAME, createInfo->strArg1,
										createInfo->strArgLen1 );
	if( cryptStatusError( status ) )
		{
		/* If we get a special-case OK status, we're in the zeroised state
		   with no user info present, make sure that the user is logging in
		   with the default SO password */
		if( status == OK_SPECIAL )
			status = ( createInfo->strArgLen2 == PRIMARYSO_PASSWORD_LENGTH && \
					   ( !memcmp( createInfo->strArg2, PRIMARYSO_PASSWORD,
								  PRIMARYSO_PASSWORD_LENGTH ) || \
						 !memcmp( createInfo->strArg2, PRIMARYSO_ALTPASSWORD,
								  PRIMARYSO_PASSWORD_LENGTH ) ) ) ? \
					 CRYPT_OK : CRYPT_ERROR_WRONGKEY;
		if( cryptStatusError( status ) )
			return( status );
		fileRef = -1;	/* No user file present yet for primary SO */

		/* We're logging in as the primary SO with the SO default password,
		   create the primary SO user object */
		assert( createInfo->strArgLen1 == primarySOInfo.userNameLength && \
				!memcmp( createInfo->strArg1, primarySOInfo.userName,
						 primarySOInfo.userNameLength ) );
		assert( createInfo->strArgLen2 == PRIMARYSO_PASSWORD_LENGTH && \
				( !memcmp( createInfo->strArg2, PRIMARYSO_PASSWORD,
						   PRIMARYSO_PASSWORD_LENGTH ) || \
				  !memcmp( createInfo->strArg2, PRIMARYSO_ALTPASSWORD,
						   PRIMARYSO_PASSWORD_LENGTH ) ) );
		initStatus = openUser( &iCryptUser, createInfo->cryptOwner,
							   &primarySOInfo, &userInfoPtr );
		}
	else
		{
		USER_FILE_INFO userFileInfo;

		/* We're in the non-zeroised state, no user can use the default SO
		   password */
		if( createInfo->strArgLen2 == PRIMARYSO_PASSWORD_LENGTH && \
			( !memcmp( createInfo->strArg2, PRIMARYSO_PASSWORD,
					   PRIMARYSO_PASSWORD_LENGTH ) || \
			  !memcmp( createInfo->strArg2, PRIMARYSO_ALTPASSWORD,
					   PRIMARYSO_PASSWORD_LENGTH ) ) )
			return( CRYPT_ERROR_WRONGKEY );

		/* Read the user info from the user file and perform access
		   verification */
		status = getCheckUserInfo( &userFileInfo, fileRef );
		if( cryptStatusError( status ) )
			return( status );

		/* Pass the call on to the lower-level open function */
		assert( createInfo->strArgLen1 == userFileInfo.userNameLength && \
				!memcmp( createInfo->strArg1, userFileInfo.userName,
						 userFileInfo.userNameLength ) );
		initStatus = openUser( &iCryptUser, createInfo->cryptOwner,
							   &userFileInfo, &userInfoPtr );
		zeroise( &userFileInfo, sizeof( USER_FILE_INFO ) );
		}
	if( userInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The init failed, make sure that the object gets destroyed when we
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptUser, IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( iCryptUser, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );

	/* If the user object has a corresponding user info file, read any
	   stored config options into the object.  We have to do this after
	   it's initialised because the config data, coming from an external
	   (and therefore untrusted) source has to go through the kernel's
	   ACL checking */
	if( fileRef >= 0 )
		{
		sPrintf_s( userFileName, 16, "u%06x", fileRef );
		readConfig( iCryptUser, userFileName, userInfoPtr->trustInfoPtr );
		}
	createInfo->cryptHandle = iCryptUser;
	return( CRYPT_OK );
	}

/* Create the default user object */

static int createDefaultUserObject( void )
	{
	CRYPT_USER iUserObject;
	USER_INFO *userInfoPtr;
	int initStatus, status;

	/* Pass the call on to the lower-level open function.  This user is
	   unique and has no owner or type.

	   Normally if an object init fails, we tell the kernel to destroy it
	   by sending it a destroy message, which is processed after the object's
	   status has been set to normal, however we don't have the privileges to
	   do this so we just pass the error code back to the caller which causes
	   the cryptlib init to fail */
	initStatus = openUser( &iUserObject, SYSTEM_OBJECT_HANDLE, &defaultUserInfo,
						   &userInfoPtr );
	if( userInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	assert( iUserObject == DEFAULTUSER_OBJECT_HANDLE );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( iUserObject, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );

	/* Read any stored config options into the object.  We have to do this
	   after it's initialised because the config data, coming from an
	   external (and therefore untrusted) source has to go through the
	   kernel's ACL checking.  If the config read succeeds, the object is
	   in the initialised state.  If the config read fails, we don't
	   propagate the error upwards since we don't want the whole cryptlib
	   init to fail because of a wrong entry in a config file */
	status = readConfig( DEFAULTUSER_OBJECT_HANDLE, "cryptlib",
						 userInfoPtr->trustInfoPtr );
	if( cryptStatusOK( status ) )
		krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );
	return( CRYPT_OK );
	}

/* Generic management function for this class of object */

int userManagementFunction( const MANAGEMENT_ACTION_TYPE action )
	{
	assert( action == MANAGEMENT_ACTION_INIT );

	switch( action )
		{
		case MANAGEMENT_ACTION_INIT:
			return( createDefaultUserObject() );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}
