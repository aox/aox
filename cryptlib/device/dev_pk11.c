/****************************************************************************
*																			*
*							cryptlib PKCS #11 Routines						*
*						Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "device.h"
  #include "asn1_rw.h"
  #include "context.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "device.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/context.h"
#else
  #include "crypt.h"
  #include "device/device.h"
  #include "misc/asn1_rw.h"
  #include "misc/context.h"
#endif /* Compiler-specific includes */

/* Before we can include the PKCS #11 headers we need to define a few OS-
   specific things that are required by the headers */

#ifdef __WINDOWS__
  #ifdef __WIN16__
	#pragma pack( 1 )					/* Struct packing */
	#define CK_PTR	far *				/* Pointer type */
	#define CK_DEFINE_FUNCTION( returnType, name ) \
								returnType __export _far _pascal name
	#define CK_DECLARE_FUNCTION( returnType, name ) \
								 returnType __export _far _pascal name
	#define CK_DECLARE_FUNCTION_POINTER( returnType, name ) \
								returnType __export _far _pascal (* name)
	#define CK_CALLBACK_FUNCTION( returnType, name ) \
								  returnType (_far _pascal * name)
  #else
	#pragma pack( push, cryptoki, 1 )	/* Struct packing */
	#define CK_PTR	*					/* Pointer type */
	#define CK_DEFINE_FUNCTION( returnType, name ) \
								returnType __declspec( dllexport ) name
	#define CK_DECLARE_FUNCTION( returnType, name ) \
								 returnType __declspec( dllimport ) name
	#define CK_DECLARE_FUNCTION_POINTER( returnType, name ) \
								returnType __declspec( dllimport ) (* name)
	#define CK_CALLBACK_FUNCTION( returnType, name ) \
								  returnType (* name)
  #endif /* Win16 vs.Win32 */
#else
  #define CK_PTR	*					/* Pointer type */
  #define CK_DEFINE_FUNCTION( returnType, name ) \
							  returnType name
  #define CK_DECLARE_FUNCTION( returnType, name ) \
							   returnType name
  #define CK_DECLARE_FUNCTION_POINTER( returnType, name ) \
									   returnType (* name)
  #define CK_CALLBACK_FUNCTION( returnType, name ) \
								returnType (* name)
#endif /* __WINDOWS__ */
#ifndef NULL_PTR
  #define NULL_PTR	NULL
#endif /* NULL_PTR */

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "pkcs11.h"
#else
  #include "device/pkcs11.h"
#endif /* Compiler-specific includes */

/* The max. number of drivers we can work with and the max.number of slots
   per driver */

#define MAX_PKCS11_DRIVERS		5
#define MAX_PKCS11_SLOTS		16

/* The default slot to look for tokens in */

#define DEFAULT_SLOT			0

/* Occasionally we need to read things into host memory from a device in a
   manner that can't be handled by a dynBuf since the data is coming from a
   device rather than a cryptlib object.  The following value defines the 
   maximum size of the on-stack buffer, if the data is larger than this we 
   dynamically allocate the buffer (this almost never occurs) */

#define MAX_BUFFER_SIZE			1024

/* Encryption contexts can store extra implementation-dependant parameters.
   The following macro maps these generic parameter names to the PKCS #11
   values */

#define paramKeyType			param1

/* Prototypes for functions in cryptcap.c */

const void FAR_BSS *findCapabilityInfo( const void FAR_BSS *capabilityInfoPtr,
										const CRYPT_ALGO_TYPE cryptAlgo );

#ifdef USE_PKCS11

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

/* Whether the PKCS #11 library has been initialised or not, this is
   initialised on demand the first time it's accessed */

static BOOLEAN pkcs11Initialised = FALSE;

#ifdef DYNAMIC_LOAD

/* Since we can be using multiple PKCS #11 drivers, we define an array of
   them and access the appropriate one by name */

typedef struct {
	char name[ 32 + 1 ];			/* Name of device */
	INSTANCE_HANDLE hPKCS11;		/* Handle to driver */
	CK_C_CloseSession pC_CloseSession;	/* Interface function pointers */
	CK_C_CreateObject pC_CreateObject;
	CK_C_Decrypt pC_Decrypt;
	CK_C_DecryptInit pC_DecryptInit;
	CK_C_DestroyObject pC_DestroyObject;
	CK_C_Encrypt pC_Encrypt;
	CK_C_EncryptInit pC_EncryptInit;
	CK_C_Finalize pC_Finalize;
	CK_C_FindObjects pC_FindObjects;
	CK_C_FindObjectsFinal pC_FindObjectsFinal;
	CK_C_FindObjectsInit pC_FindObjectsInit;
	CK_C_GenerateKeyPair pC_GenerateKeyPair;
	CK_C_GenerateRandom pC_GenerateRandom;
	CK_C_GetAttributeValue pC_GetAttributeValue;
	CK_C_GetMechanismInfo pC_GetMechanismInfo;
	CK_C_GetSlotInfo pC_GetSlotInfo;
	CK_C_GetSlotList pC_GetSlotList;
	CK_C_GetTokenInfo pC_GetTokenInfo;
	CK_C_InitPIN pC_InitPIN;
	CK_C_InitToken pC_InitToken;
	CK_C_Login pC_Login;
	CK_C_Logout pC_Logout;
	CK_C_OpenSession pC_OpenSession;
	CK_C_SetAttributeValue pC_SetAttributeValue;
	CK_C_SetPIN pC_SetPIN;
	CK_C_Sign pC_Sign;
	CK_C_SignInit pC_SignInit;
	CK_C_UnwrapKey pC_UnwrapKey;
	CK_C_Verify pC_Verify;
	CK_C_VerifyInit pC_VerifyInit;
	} PKCS11_DRIVER_INFO;

static PKCS11_DRIVER_INFO pkcs11InfoTbl[ MAX_PKCS11_DRIVERS ];

/* The use of dynamically bound function pointers vs.statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define C_CloseSession		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_CloseSession
#define C_CreateObject		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_CreateObject
#define C_Decrypt			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_Decrypt
#define C_DecryptInit		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_DecryptInit
#define C_DestroyObject		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_DestroyObject
#define C_Encrypt			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_Encrypt
#define C_EncryptInit		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_EncryptInit
#define C_Finalize			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_Finalize
#define C_FindObjects		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_FindObjects
#define C_FindObjectsFinal	pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_FindObjectsFinal
#define C_FindObjectsInit	pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_FindObjectsInit
#define C_GenerateKeyPair	pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_GenerateKeyPair
#define C_GenerateRandom	pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_GenerateRandom
#define C_GetAttributeValue	pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_GetAttributeValue
#define C_GetMechanismInfo	pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_GetMechanismInfo
#define C_GetSlotInfo		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_GetSlotInfo
#define C_GetSlotList		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_GetSlotList
#define C_GetTokenInfo		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_GetTokenInfo
#define C_Initialize		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_Initialize
#define C_InitPIN			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_InitPIN
#define C_InitToken			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_InitToken
#define C_Login				pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_Login
#define C_Logout			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_Logout
#define C_OpenSession		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_OpenSession
#define C_SetAttributeValue	pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_SetAttributeValue
#define C_SetPIN			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_SetPIN
#define C_Sign				pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_Sign
#define C_SignInit			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_SignInit
#define C_UnwrapKey			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_UnwrapKey
#define C_Verify			pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_Verify
#define C_VerifyInit		pkcs11InfoTbl[ pkcs11Info->deviceNo ].pC_VerifyInit

/* Dynamically load and unload any necessary PKCS #11 drivers */

static int loadPKCS11driver( PKCS11_DRIVER_INFO *pkcs11Info,
							 const char *driverName )
	{
	CK_C_GetInfo pC_GetInfo;
	CK_C_Initialize pC_Initialize;
	CK_INFO info;
	CK_RV status;
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */
	BOOLEAN isInitialised = FALSE;
	int i = 32;

	/* Obtain a handle to the device driver module */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	pkcs11Info->hPKCS11 = LoadLibrary( driverName );
	SetErrorMode( errorMode );
	if( pkcs11Info->hPKCS11 < HINSTANCE_ERROR )
		{
		pkcs11Info->hPKCS11 = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}
#else
	if( ( pkcs11Info->hPKCS11 = DynamicLoad( driverName ) ) == NULL_INSTANCE )
		return( CRYPT_ERROR );
#endif /* OS-specific dynamic load */

	/* Now get pointers to the functions */
	pC_GetInfo = ( CK_C_GetInfo ) DynamicBind( pkcs11Info->hPKCS11, "C_GetInfo" );
	pC_Initialize = ( CK_C_Initialize ) DynamicBind( pkcs11Info->hPKCS11, "C_Initialize" );
	pkcs11Info->pC_CloseSession = ( CK_C_CloseSession ) DynamicBind( pkcs11Info->hPKCS11, "C_CloseSession" );
	pkcs11Info->pC_CreateObject = ( CK_C_CreateObject ) DynamicBind( pkcs11Info->hPKCS11, "C_CreateObject" );
	pkcs11Info->pC_Decrypt = ( CK_C_Decrypt ) DynamicBind( pkcs11Info->hPKCS11, "C_Decrypt" );
	pkcs11Info->pC_DecryptInit = ( CK_C_DecryptInit ) DynamicBind( pkcs11Info->hPKCS11, "C_DecryptInit" );
	pkcs11Info->pC_DestroyObject = ( CK_C_DestroyObject ) DynamicBind( pkcs11Info->hPKCS11, "C_DestroyObject" );
	pkcs11Info->pC_Encrypt = ( CK_C_Encrypt ) DynamicBind( pkcs11Info->hPKCS11, "C_Encrypt" );
	pkcs11Info->pC_EncryptInit = ( CK_C_EncryptInit ) DynamicBind( pkcs11Info->hPKCS11, "C_EncryptInit" );
	pkcs11Info->pC_Finalize = ( CK_C_Finalize ) DynamicBind( pkcs11Info->hPKCS11, "C_Finalize" );
	pkcs11Info->pC_FindObjects = ( CK_C_FindObjects ) DynamicBind( pkcs11Info->hPKCS11, "C_FindObjects" );
	pkcs11Info->pC_FindObjectsFinal = ( CK_C_FindObjectsFinal ) DynamicBind( pkcs11Info->hPKCS11, "C_FindObjectsFinal" );
	pkcs11Info->pC_FindObjectsInit = ( CK_C_FindObjectsInit ) DynamicBind( pkcs11Info->hPKCS11, "C_FindObjectsInit" );
	pkcs11Info->pC_GenerateKeyPair = ( CK_C_GenerateKeyPair ) DynamicBind( pkcs11Info->hPKCS11, "C_GenerateKeyPair" );
	pkcs11Info->pC_GenerateRandom = ( CK_C_GenerateRandom ) DynamicBind( pkcs11Info->hPKCS11, "C_GenerateRandom" );
	pkcs11Info->pC_GetAttributeValue = ( CK_C_GetAttributeValue ) DynamicBind( pkcs11Info->hPKCS11, "C_GetAttributeValue" );
	pkcs11Info->pC_GetMechanismInfo = ( CK_C_GetMechanismInfo ) DynamicBind( pkcs11Info->hPKCS11, "C_GetMechanismInfo" );
	pkcs11Info->pC_GetSlotInfo = ( CK_C_GetSlotInfo ) DynamicBind( pkcs11Info->hPKCS11, "C_GetSlotInfo" );
	pkcs11Info->pC_GetSlotList = ( CK_C_GetSlotList ) DynamicBind( pkcs11Info->hPKCS11, "C_GetSlotList" );
	pkcs11Info->pC_GetTokenInfo = ( CK_C_GetTokenInfo ) DynamicBind( pkcs11Info->hPKCS11, "C_GetTokenInfo" );
	pkcs11Info->pC_InitPIN = ( CK_C_InitPIN ) DynamicBind( pkcs11Info->hPKCS11, "C_InitPIN" );
	pkcs11Info->pC_InitToken = ( CK_C_InitToken ) DynamicBind( pkcs11Info->hPKCS11, "C_InitToken" );
	pkcs11Info->pC_Login = ( CK_C_Login ) DynamicBind( pkcs11Info->hPKCS11, "C_Login" );
	pkcs11Info->pC_Logout = ( CK_C_Logout ) DynamicBind( pkcs11Info->hPKCS11, "C_Logout" );
	pkcs11Info->pC_OpenSession = ( CK_C_OpenSession ) DynamicBind( pkcs11Info->hPKCS11, "C_OpenSession" );
	pkcs11Info->pC_SetAttributeValue = ( CK_C_SetAttributeValue ) DynamicBind( pkcs11Info->hPKCS11, "C_SetAttributeValue" );
	pkcs11Info->pC_SetPIN = ( CK_C_SetPIN ) DynamicBind( pkcs11Info->hPKCS11, "C_SetPIN" );
	pkcs11Info->pC_Sign = ( CK_C_Sign ) DynamicBind( pkcs11Info->hPKCS11, "C_Sign" );
	pkcs11Info->pC_SignInit = ( CK_C_SignInit ) DynamicBind( pkcs11Info->hPKCS11, "C_SignInit" );
	pkcs11Info->pC_UnwrapKey = ( CK_C_UnwrapKey ) DynamicBind( pkcs11Info->hPKCS11, "C_UnwrapKey" );
	pkcs11Info->pC_Verify = ( CK_C_Verify ) DynamicBind( pkcs11Info->hPKCS11, "C_Verify" );
	pkcs11Info->pC_VerifyInit = ( CK_C_VerifyInit ) DynamicBind( pkcs11Info->hPKCS11, "C_VerifyInit" );

	/* Make sure we got valid pointers for every device function.  
	   C_FindObjectsFinal() wasn't added until 2.x and some drivers don't
	   implement it (a smaller subset of them nevertheless claim to be 2.x 
	   drivers), so we allow this to be null - the code won't call it if it's
	   not present */
	if( pC_GetInfo == NULL || pC_Initialize == NULL ||
		pkcs11Info->pC_CloseSession == NULL ||
		pkcs11Info->pC_CreateObject == NULL ||
		pkcs11Info->pC_Decrypt == NULL ||
		pkcs11Info->pC_DecryptInit == NULL ||
		pkcs11Info->pC_DestroyObject == NULL ||
		pkcs11Info->pC_Encrypt == NULL ||
		pkcs11Info->pC_EncryptInit == NULL ||
		pkcs11Info->pC_Finalize == NULL ||
		pkcs11Info->pC_FindObjects == NULL ||
		pkcs11Info->pC_FindObjectsInit == NULL ||
		pkcs11Info->pC_GenerateRandom == NULL ||
		pkcs11Info->pC_GenerateKeyPair == NULL ||
		pkcs11Info->pC_GetAttributeValue == NULL ||
		pkcs11Info->pC_GetMechanismInfo == NULL ||
		pkcs11Info->pC_GetSlotInfo == NULL ||
		pkcs11Info->pC_GetSlotList == NULL ||
		pkcs11Info->pC_GetTokenInfo == NULL || 
		pkcs11Info->pC_InitPIN == NULL || 
		pkcs11Info->pC_InitToken == NULL || pkcs11Info->pC_Login == NULL ||
		pkcs11Info->pC_Logout == NULL || pkcs11Info->pC_OpenSession == NULL ||
		pkcs11Info->pC_SetAttributeValue == NULL ||
		pkcs11Info->pC_SetPIN == NULL || pkcs11Info->pC_Sign == NULL ||
		pkcs11Info->pC_SignInit == NULL || pkcs11Info->pC_UnwrapKey == NULL || 
		pkcs11Info->pC_Verify == NULL || pkcs11Info->pC_VerifyInit == NULL )
		{
		/* Free the library reference and clear the info */
		DynamicUnload( pkcs11Info->hPKCS11 );
		memset( pkcs11Info, 0, sizeof( PKCS11_DRIVER_INFO ) );
		return( CRYPT_ERROR );
		}

	/* Initialise the PKCS #11 library and get info on the device.  There are 
	   four types of PKCS #11 driver around: v1, v1-like claiming to be v2, 
	   v2-like claiming to be v1, and v2.  cryptlib can in theory handle all 
	   of these, however there are some problem areas with v1 (for example v1 
	   uses 16-bit values while v2 uses 32-bit ones, this is usually OK 
	   because data is passed around as 32-bit values with the high bits 
	   zeroed but some implementations may leave garbage in the high 16 bits 
	   that leads to all sorts of confusion).  Because of this we explicitly 
	   fail if something claims to be v1 even though it might work in 
	   practice */
	status = pC_Initialize( NULL_PTR ) & 0xFFFF;
	if( status == CKR_OK )
		{
		isInitialised = TRUE;
		status = pC_GetInfo( &info ) & 0xFFFF;
		}
	if( status == CKR_OK && info.cryptokiVersion.major <= 1 )
		/* It's v1, we can't work with it */
		status = CKR_FUNCTION_NOT_SUPPORTED;
	if( status != CKR_OK )
		{
		if( isInitialised )
			pkcs11Info->pC_Finalize( NULL_PTR );
		DynamicUnload( pkcs11Info->hPKCS11 );
		memset( pkcs11Info, 0, sizeof( PKCS11_DRIVER_INFO ) );
		return( CRYPT_ERROR );
		}

	/* Copy out the device driver's name so that the user can access it by 
	   name.  Some vendors erroneously null-terminate the string so we check 
	   for nulls as well */
	memcpy( pkcs11Info->name, info.libraryDescription, 32 );
	while( i > 0 && ( pkcs11Info->name[ i - 1 ] == ' ' || \
					  !pkcs11Info->name[ i - 1 ] ) )
		i--;
	pkcs11Info->name[ i ] = '\0';

	return( CRYPT_OK );
	}

void deviceEndPKCS11( void )
	{
	int i;

	if( pkcs11Initialised )
		for( i = 0; i < MAX_PKCS11_DRIVERS; i++ )
			{
			if( pkcs11InfoTbl[ i ].hPKCS11 != NULL_INSTANCE )
				{
				pkcs11InfoTbl[ i ].pC_Finalize( NULL_PTR );
				DynamicUnload( pkcs11InfoTbl[ i ].hPKCS11 );
				}
			pkcs11InfoTbl[ i ].hPKCS11 = NULL_INSTANCE;
			}
	pkcs11Initialised = FALSE;
	}

int deviceInitPKCS11( void )
	{
	int tblIndex = 0, optionIndex;

	/* If we've previously tried to init the drivers, don't try it again */
	if( pkcs11Initialised )
		return( CRYPT_OK );
	memset( pkcs11InfoTbl, 0, sizeof( pkcs11InfoTbl ) );

	/* Try and link in each driver specified in the config options.  Since
	   this is a general systemwide config option, we always query the built-
	   in default user object */
	for( optionIndex = 0; optionIndex < MAX_PKCS11_DRIVERS; optionIndex++ )
		{
		RESOURCE_DATA msgData;
		char deviceDriverName[ MAX_PATH_LENGTH + 1 ];
		int status;

		setMessageData( &msgData, deviceDriverName, MAX_PATH_LENGTH );
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
						IMESSAGE_GETATTRIBUTE_S, &msgData, 
						optionIndex + CRYPT_OPTION_DEVICE_PKCS11_DVR01 );
		if( cryptStatusError( status ) )
			continue;
		deviceDriverName[ msgData.length ] = '\0';
		status = loadPKCS11driver( &pkcs11InfoTbl[ tblIndex ], 
								   deviceDriverName );
		if( cryptStatusOK( status ) )
			{
			tblIndex++;
			pkcs11Initialised = TRUE;
			}
		}
	
	return( CRYPT_OK );
	}

#else

int deviceInitPKCS11( void )
	{
	/* If we've previously tried to init the drivers, don't try it again */
	if( pkcs11Initialised )
		return( CRYPT_OK );

	if( C_Initialize( NULL_PTR ) != CKR_OK )
		return( CRYPT_ERROR );
	pkcs11Initialised = TRUE;
	return( CRYPT_OK );
	}

void deviceEndPKCS11( void )
	{
	if( pkcs11Initialised )
		C_Finalize( NULL_PTR );
	pkcs11Initialised = FALSE;
	}
#endif /* DYNAMIC_LOAD */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a PKCS #11-specific error to a cryptlib error */

static int mapError( PKCS11_INFO *pkcs11Info, const CK_RV errorCode,
					 const int defaultError )
	{
	pkcs11Info->errorCode = ( int ) errorCode;
	switch( ( int ) errorCode )
		{
		case CKR_OK:
			return( CRYPT_OK );

		case CKR_HOST_MEMORY:
		case CKR_DEVICE_MEMORY:
			return( CRYPT_ERROR_MEMORY );

		case CKR_DEVICE_ERROR:
		case CKR_DEVICE_REMOVED:
		case CKR_TOKEN_NOT_PRESENT:
		case CKR_TOKEN_NOT_RECOGNIZED:
			return( CRYPT_ERROR_SIGNALLED );

		case CKR_PIN_INCORRECT:
		case CKR_PIN_INVALID:
		case CKR_PIN_LEN_RANGE:
		case CKR_PIN_EXPIRED:
		case CKR_PIN_LOCKED:
			return( CRYPT_ERROR_WRONGKEY );

		case CKR_DATA_INVALID:
		case CKR_ENCRYPTED_DATA_INVALID:
		case CKR_WRAPPED_KEY_INVALID:
			return( CRYPT_ERROR_BADDATA );

		case CKR_SIGNATURE_INVALID:
			return( CRYPT_ERROR_SIGNATURE );

		case CKR_KEY_NOT_WRAPPABLE:
		case CKR_KEY_UNEXTRACTABLE:
		case CKR_TOKEN_WRITE_PROTECTED:
		case CKR_INFORMATION_SENSITIVE:
			return( CRYPT_ERROR_PERMISSION );

		case CKR_DATA_LEN_RANGE:
		case CKR_ENCRYPTED_DATA_LEN_RANGE:
		case CKR_SIGNATURE_LEN_RANGE:
		case CKR_UNWRAPPING_KEY_SIZE_RANGE:
		case CKR_WRAPPING_KEY_SIZE_RANGE:
		case CKR_WRAPPED_KEY_LEN_RANGE:
			return( CRYPT_ERROR_OVERFLOW );

		case CKR_SESSION_EXISTS:
		case CKR_SESSION_READ_ONLY_EXISTS:
		case CKR_SESSION_READ_WRITE_SO_EXISTS:
		case CKR_USER_ALREADY_LOGGED_IN:
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
		case CKR_CRYPTOKI_NOT_INITIALIZED:
			return( CRYPT_ERROR_INITED );

		case CKR_USER_NOT_LOGGED_IN:
		case CKR_USER_PIN_NOT_INITIALIZED:
		case CKR_CRYPTOKI_ALREADY_INITIALIZED:
			return( CRYPT_ERROR_NOTINITED );

		case CKR_RANDOM_NO_RNG:
			return( CRYPT_ERROR_RANDOM );

		case CKR_OPERATION_ACTIVE:
			return( CRYPT_ERROR_TIMEOUT );
		}

	return( defaultError );
	}

/* Extract the time from a PKCS #11 tokenInfo structure */

static time_t getTokenTime( CK_TOKEN_INFO *tokenInfo )
	{
	STREAM stream;
	BYTE buffer[ 32 ];
	time_t theTime = MIN_TIME_VALUE + 1;
	int length, status;

	/* Convert the token time to an ASN.1 time string that we can read using
	   the standard ASN.1 routines by writing a dummy time value and inserting 
	   the token's time string in its place */
	sMemOpen( &stream, buffer, 32 );
	writeGeneralizedTime( &stream, theTime, DEFAULT_TAG );
	length = stell( &stream );
	sMemDisconnect( &stream );
	memcpy( buffer + 2, tokenInfo->utcTime, 14 );
	sMemConnect( &stream, buffer, length );
	status = readGeneralizedTime( &stream, &theTime );
	sMemDisconnect( &stream );
	
	return( ( cryptStatusOK( status ) ) ? theTime : 0 );
	}

/* Find an object based on a given template.  There are two variations of 
   this, one that finds one and only one object, and the other that returns 
   the first object it finds without treating the presence of multiple 
   objects as an error.
   
   The way in which this call works has special significance, there are PKCS
   #11 implementations that don't allow any other calls during the init/find/
   final sequence, so the code is structured to always call them one after 
   the other without any intervening calls.  In addition some drivers are
   confused over whether they're 1.x or 2.x and may or may not implement
   C_FindObjectsFinal().  Because of this we call it if it exists, if it 
   doesn't we assume that the driver can handle cleanup itself (this 
   situation shouldn't occur because we've checked for 1.x drivers earlier, 
   but there are one or two drivers where it does happen) */

static int findDeviceObjects( PKCS11_INFO *pkcs11Info, 
							  CK_OBJECT_HANDLE *hObject,
							  const CK_ATTRIBUTE *objectTemplate,
							  const CK_ULONG templateCount,
							  const BOOLEAN onlyOne )
	{
	CK_OBJECT_HANDLE hObjectArray[ 2 ];
	CK_ULONG ulObjectCount;
	CK_RV status;

	status = C_FindObjectsInit( pkcs11Info->hSession,
								( CK_ATTRIBUTE_PTR ) objectTemplate,
								templateCount );
	if( status == CKR_OK )
		{
		status = C_FindObjects( pkcs11Info->hSession, hObjectArray, 
								2, &ulObjectCount );
		if( C_FindObjectsFinal != NULL )
			C_FindObjectsFinal( pkcs11Info->hSession );
		}
	if( status != CKR_OK )
		return( mapError( pkcs11Info, status, CRYPT_ERROR_NOTFOUND ) );
	if( ulObjectCount <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	if( ulObjectCount > 1 && onlyOne )
		return( CRYPT_ERROR_DUPLICATE );
	if( hObject != NULL )
		*hObject = hObjectArray[ 0 ];

	return( CRYPT_OK );
	}

static int findObject( PKCS11_INFO *pkcs11Info, CK_OBJECT_HANDLE *hObject,
					   const CK_ATTRIBUTE *objectTemplate,
					   const CK_ULONG templateCount )
	{
	return( findDeviceObjects( pkcs11Info, hObject, 
							   objectTemplate, templateCount, TRUE ) );
	}

static int findObjectEx( PKCS11_INFO *pkcs11Info, CK_OBJECT_HANDLE *hObject,
						 const CK_ATTRIBUTE *objectTemplate,
						 const CK_ULONG templateCount )
	{
	return( findDeviceObjects( pkcs11Info, hObject, 
							   objectTemplate, templateCount, FALSE ) );
	}

/* Set up certificate information and load it into the card */

static int updateCertificate( PKCS11_INFO *pkcs11Info, 
							  const CRYPT_HANDLE iCryptHandle )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	static const CK_BBOOL bTrue = TRUE;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_ID, NULL_PTR, 0 },
		{ CKA_SUBJECT, NULL_PTR, 0 },
		{ CKA_ISSUER, NULL_PTR, 0 },
		{ CKA_SERIAL_NUMBER, NULL_PTR, 0 },
		{ CKA_VALUE, NULL_PTR, 0 },
		};
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &privkeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_ID, NULL_PTR, 0 }
		};
	CK_OBJECT_HANDLE hObject;
	CK_RV status;
	RESOURCE_DATA msgData;
	STREAM stream;
	DYNBUF subjectDB, iAndSDB, certDB;
	BYTE keyID[ CRYPT_MAX_HASHSIZE ];
	int length, cryptStatus;

	/* Get the key ID for the cert and use it to locate the corresponding
	   public or private key object.  This is used as a check to ensure that 
	   the certificate corresponds to a key in the device.  In theory this 
	   would allow us to read the label from the key so that we can reuse it 
	   for the cert, but there doesn't seem to be any good reason for this 
	   and it could lead to problems with multiple certs with the same 
	   labels so we don't do it */
	setMessageData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
	cryptStatus = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								   &msgData, CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusError( cryptStatus ) )
		return( CRYPT_ARGERROR_NUM1 );
	keyTemplate[ 1 ].pValue = msgData.data;
	keyTemplate[ 1 ].ulValueLen = msgData.length;
	cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 2 );
	if( cryptStatusError( cryptStatus ) )
		{
		/* Couldn't find a private key with this ID, try for a public key */
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubkeyClass;
		cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 2 );
		}
	if( cryptStatusError( cryptStatus ) )
		return( CRYPT_ARGERROR_NUM1 );
	certTemplate[ 3 ].pValue = msgData.data;
	certTemplate[ 3 ].ulValueLen = msgData.length;

	/* Get the subjectName from the cert */
	cryptStatus = dynCreate( &subjectDB, iCryptHandle, 
							 CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	certTemplate[ 4 ].pValue = dynData( subjectDB );
	certTemplate[ 4 ].ulValueLen = dynLength( subjectDB );

	/* Get the issuerAndSerialNumber from the cert */
	cryptStatus = dynCreate( &iAndSDB, iCryptHandle, 
							 CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( cryptStatus ) )
		{
		dynDestroy( &subjectDB );
		return( cryptStatus );
		}
	sMemConnect( &stream, dynData( iAndSDB ), dynLength( iAndSDB ) );
	readSequence( &stream, NULL );
	certTemplate[ 5 ].pValue = sMemBufPtr( &stream );
	readSequence( &stream, &length );		/* Issuer DN */
	certTemplate[ 5 ].ulValueLen = ( int ) sizeofObject( length );
	sSkip( &stream, length );
	certTemplate[ 6 ].pValue = sMemBufPtr( &stream );
	readGenericHole( &stream, &length, BER_INTEGER );/* Serial number */
	certTemplate[ 6 ].ulValueLen = ( int ) sizeofObject( length );
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );

	/* Get the certificate data */
	cryptStatus = dynCreate( &certDB, iCryptHandle, 
							 CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusError( cryptStatus ) )
		{
		dynDestroy( &subjectDB );
		dynDestroy( &iAndSDB );
		return( cryptStatus );
		}
	certTemplate[ 7 ].pValue = dynData( certDB );
	certTemplate[ 7 ].ulValueLen = dynLength( certDB );

	/* We've finally got everything available, try and update the device with
	   the certificate data.  In theory we should also set CKA_PRIVATE = FALSE
	   but the Dallas iButton driver doesn't allow this so we have to rely on
	   drivers doing the right thing with the default setting */
	status = C_CreateObject( pkcs11Info->hSession,
							 ( CK_ATTRIBUTE_PTR ) certTemplate, 8, 
							 &hObject );
	if( status != CKR_OK )
		cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );

	/* Clean up */
	dynDestroy( &subjectDB );
	dynDestroy( &iAndSDB );
	dynDestroy( &certDB );
	return( cryptStatus );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Prototypes for functions to get and free device capability information */

static int getCapabilities( DEVICE_INFO *deviceInfo );
static void freeCapabilities( DEVICE_INFO *deviceInfo );

/* Prototypes for device-specific functions */

static int getRandomFunction( DEVICE_INFO *deviceInfo, void *buffer,
							  const int length );

/* Close a previously-opened session with the device.  We have to have this
   before the init function since it may be called by it if the init process
   fails */

static void shutdownFunction( DEVICE_INFO *deviceInfo )
	{
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;

	/* Log out and close the session with the device */
	if( deviceInfo->flags & DEVICE_LOGGEDIN )
		C_Logout( pkcs11Info->hSession );
	C_CloseSession( pkcs11Info->hSession );
	pkcs11Info->hSession = CRYPT_ERROR;
	deviceInfo->flags &= ~( DEVICE_ACTIVE | DEVICE_LOGGEDIN );

	/* Free the device capability information */
	freeCapabilities( deviceInfo );
	}

/* Open a session with the device */

static int initFunction( DEVICE_INFO *deviceInfo, const char *name,
						 const int nameLength )
	{
	CK_SESSION_HANDLE hSession;
	CK_SLOT_ID slotList[ MAX_PKCS11_SLOTS ];
	CK_ULONG slotCount = MAX_PKCS11_SLOTS;
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
	CK_RV status;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	char *labelPtr;
	int tokenSlot = DEFAULT_SLOT, i, labelLength, cryptStatus;

	/* Get information on all available slots */
	memset( slotList, 0, sizeof( slotList ) );
	status = C_GetSlotList( TRUE, slotList, &slotCount );
	if( status != CKR_OK )
		return( mapError( pkcs11Info, status, CRYPT_ERROR_OPEN ) );
	if( slotCount <= 0 )	/* Can happen in some circumstances */
		return( CRYPT_ERROR_OPEN );

	/* Check whether a token name (used to select the slot) has been 
	   specified */
	for( i = 1; i < nameLength - 1; i++ )
		if( name[ i ] == ':' && name[ i + 1 ] == ':' )
			{
			const void *tokenName = name + i + 2;	/* Skip '::' */
			const int tokenNameLength = nameLength - ( i + 2 );

			if( tokenNameLength <= 0 )
				return( CRYPT_ARGERROR_STR1 );

			/* Check each slot for a token matching the given name */
			for( tokenSlot = 0; tokenSlot < slotCount; tokenSlot++ )
				{
				status = C_GetTokenInfo( slotList[ tokenSlot ], &tokenInfo );
				if( status == CKR_OK && \
					!strnicmp( tokenName, tokenInfo.label, tokenNameLength ) )
					break;
				};
			if( tokenSlot == slotCount )
				return( CRYPT_ERROR_NOTFOUND );
			}
	pkcs11Info->slotID = slotList[ tokenSlot ];

	/* Get information on device-specific capabilities */
	status = C_GetSlotInfo( pkcs11Info->slotID, &slotInfo );
	if( status != CKR_OK )
		{
		shutdownFunction( deviceInfo );
		return( mapError( pkcs11Info, status, CRYPT_ERROR_OPEN ) );
		}
	if( slotInfo.flags & CKF_REMOVABLE_DEVICE )
		/* The device is removable */
		deviceInfo->flags |= DEVICE_REMOVABLE;
	status = C_GetTokenInfo( pkcs11Info->slotID, &tokenInfo );
	if( status != CKR_OK )
		{
		shutdownFunction( deviceInfo );
		return( mapError( pkcs11Info, status, CRYPT_ERROR_OPEN ) );
		}
	if( tokenInfo.flags & CKF_RNG )
		/* The device has an onboard RNG that we can use */
		deviceInfo->getRandomFunction = getRandomFunction;
	if( tokenInfo.flags & CKF_CLOCK_ON_TOKEN )
		{
		const time_t theTime = getTokenTime( &tokenInfo );
		const time_t currentTime = getTime();

		/* The token claims to have an onboard clock that we can use.  Since
		   this could be arbitrarily inaccurate, we compare it with the 
		   system time and only rely on it if it's within +/- 1 day of the
		   system time */
		if( theTime >= currentTime - 86400 && \
			theTime <= currentTime + 86400 )
			deviceInfo->flags |= DEVICE_TIME;
		}
	if( tokenInfo.flags & CKF_WRITE_PROTECTED )
		/* The device can't have data on it changed */
		deviceInfo->flags |= DEVICE_READONLY;
	if( tokenInfo.flags & CKF_LOGIN_REQUIRED )
		/* The user needs to log in before using various device functions */
		deviceInfo->flags |= DEVICE_NEEDSLOGIN;
	if( ( pkcs11Info->minPinSize = ( int ) tokenInfo.ulMinPinLen ) < 4 )
		/* Some devices report silly PIN sizes */
		pkcs11Info->minPinSize = 4;
	if( ( pkcs11Info->maxPinSize = ( int ) tokenInfo.ulMaxPinLen ) < 4 )
		/* Some devices report silly PIN sizes (setting this to ULONG_MAX or
		   4GB, which becomes -1 as an int, counts as silly).  Since we can't
		   differentiate between 0xFFFFFFFF = bogus value and 0xFFFFFFFF = 
		   ULONG_MAX we play it safe and set the limit to 8 bytes, which most
		   devices should be able to handle */
		pkcs11Info->maxPinSize = 8;
	labelPtr = tokenInfo.label;
	for( labelLength = 32;
		 labelLength > 0 && \
		 ( labelPtr[ labelLength - 1 ] == ' ' || \
		   !labelPtr[ labelLength - 1 ] ); 
		  labelLength-- );	/* Strip trailing blanks/nulls */
	while( labelLength > 0 && *labelPtr == ' ' )
		{
		/* Strip leading blanks */
		labelPtr++;
		labelLength--;
		}
	if( labelLength > 0 )
		{
		memcpy( pkcs11Info->labelBuffer, labelPtr, labelLength );
		pkcs11Info->labelBuffer[ labelLength ] = '\0';
		deviceInfo->label = pkcs11Info->labelBuffer;
		}
	else
		{
		/* There's no label for the token, use the device label instead */
		if( pkcs11InfoTbl[ pkcs11Info->deviceNo ].name[ 0 ] )
			{
			strcpy( pkcs11Info->labelBuffer, 
					pkcs11InfoTbl[ pkcs11Info->deviceNo ].name );
			deviceInfo->label = pkcs11Info->labelBuffer;
			}
		}

	/* Open a session with the device.  This gets a bit awkward because we 
	   can't tell whether a R/W session is OK without opening a session, but 
	   we can't open a session unless we know whether a R/W session is OK, 
	   so we first try for a RW session and if that fails we go for a read-
	   only session */
	status = C_OpenSession( pkcs11Info->slotID, 
							CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL_PTR, 
							NULL_PTR, &hSession );
	if( status == CKR_TOKEN_WRITE_PROTECTED )
		status = C_OpenSession( pkcs11Info->slotID, 
								CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, 
								&hSession );
	if( status != CKR_OK )
		{
		cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_OPEN );
		if( cryptStatus == CRYPT_ERROR_OPEN && \
			!( tokenInfo.flags & CKF_USER_PIN_INITIALIZED ) )
			/* We couldn't do much with the error code, it could be that the
			   token hasn't been initialised yet but unfortunately PKCS #11 
			   doesn't define an error code for this condition.  In addition
			   many tokens will allow a session to be opened and then fail 
			   with a "PIN not set" error at a later point (which allows for
			   more accurate error reporting), however a small number won't
			   allow a session to be opened and return some odd-looking error
			   because there's nothing useful available.  The best way to
			   report this in a meaningful manner to the caller is to check
			   whether the user PIN has been initialised, if it hasn't then 
			   it's likely that the token as a whole hasn't been initialised 
			   so we return a not initialised error */
			cryptStatus = CRYPT_ERROR_NOTINITED;
		return( cryptStatus );
		}
	pkcs11Info->hSession = hSession;
	deviceInfo->flags |= DEVICE_ACTIVE;

	/* Set up the capability information for this device */
	cryptStatus = getCapabilities( deviceInfo );
	if( cryptStatusError( cryptStatus ) )
		{
		shutdownFunction( deviceInfo );
		return( ( cryptStatus == CRYPT_ERROR ) ? \
				CRYPT_ERROR_OPEN : ( int ) cryptStatus );
		}

	return( CRYPT_OK );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_ATTRIBUTE_TYPE type,
							const void *data, const int dataLength )
	{
	CK_RV status;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;

	/* Handle token present/active checks */
	if( type == CRYPT_DEVINFO_LOGGEDIN )
		{
		CK_TOKEN_INFO tokenInfo;
		CK_SLOT_INFO slotInfo;

		/* Check whether the user is still logged in.  This is rather 
		   problematic because some devices can't detect a token removal, 
		   and if they do they often can't report it to the driver.  It's 
		   also possible in some devices to remove the token and re-insert 
		   it later without that being regarded as logging out (or you can 
		   remove the smart card and insert your frequent flyer card and 
		   it's still regarded as a card present).  In addition if the 
		   reader supports its own authentication mechanisms (even if it 
		   forces a logout if the token is removed) it's possible for the 
		   user to reinsert the token and reauthenticate themselves and it 
		   appears as if they never logged out.  In fact the only totally 
		   foolproof way to detect a token removal/change is to try and use 
		   the token to perform a crypto operation, which is a rather 
		   suboptimal detection mechanism.

		   Because of this, the best that we can do here is check the token-
		   present flag and report a token-changed error if it's not set.  
		   In addition since some devices only do a minimal check with
		   C_GetSlotInfo() (e.g. checking whether a microswitch is held
		   open by something in the slot, see above) we first call
		   C_GetTokenInfo(), which has a greater chance of actually trying
		   to access the token, before we call C_GetSlotInfo().

		   If there's a problem reported, we don't perform an implicit 
		   shutdown since the user may choose to re-authenticate to the 
		   device or perform some other action that we have no control over 
		   in response to the token-removed notification */
		status = C_GetTokenInfo( pkcs11Info->slotID, &tokenInfo );
		if( status == CKR_OK )
			status = C_GetSlotInfo( pkcs11Info->slotID, &slotInfo );
		if( status != CKR_OK )
			return( mapError( pkcs11Info, status, CRYPT_ERROR_SIGNALLED ) );
		if( !( slotInfo.flags & CKF_TOKEN_PRESENT ) )
			return( CRYPT_ERROR_SIGNALLED );

		return( CRYPT_OK );
		}

	/* Handle user authorisation */
	if( type == CRYPT_DEVINFO_AUTHENT_USER || \
		type == CRYPT_DEVINFO_AUTHENT_SUPERVISOR )
		{
		/* If the user is already logged in, log them out before we try
		   logging in with a new authentication value */
		if( deviceInfo->flags & DEVICE_LOGGEDIN )
			{
			C_Logout( pkcs11Info->hSession );
			deviceInfo->flags &= ~DEVICE_LOGGEDIN;
			}

		/* Authenticate the user to the device */
		status = C_Login( pkcs11Info->hSession,
						  ( type == CRYPT_DEVINFO_AUTHENT_USER ) ? \
						  CKU_USER : CKU_SO, ( CK_CHAR_PTR ) data,
						  ( CK_ULONG ) dataLength );
		if( status != CKR_OK && status != CKR_USER_ALREADY_LOGGED_IN )
			return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );

		/* The device is now ready for use */
		deviceInfo->flags |= DEVICE_LOGGEDIN;
		return( CRYPT_OK );
		}

	/* Handle authorisation value changes.  The init SO/user PIN 
	   functionality is a bit awkward in that it has to fill the gap between 
	   C_InitToken() (which usually sets the SSO PIN but may also take an
	   initialisation PIN and leave the token in a state where the only valid
	   operation is to set the SSO PIN) and C_SetPIN() (which can only set the 
	   SSO PIN for the SSO or the user PIN for the user).  Setting the user 
	   PIN by the SSO, which is usually required to perform any useful (non-
	   administrative) function with the token, requires the special-case 
	   C_InitPIN().  In addition we can't speculatively set the user PIN to 
	   be the same as the SSO PIN (which would be useful because in most 
	   cases the user *is* the SSO, thus ensuring that the device behaves as 
	   expected when the user isn't even aware that there are SSO and user 
	   roles) because devices that implement an FSM for initialisation will 
	   move into an undesired state once the SSO -> user change is triggered.

	   The FSM for initialisation on devices that perform a multi-stage
	   bootstrap and require all of the various intialisation functions to
	   be used one after the other (e.g. Fortezza) is:

			uninitialised/zeroised
					v
				C_InitToken			(enter init or SSO PIN)
					v
				initialised
					v
				C_SetPIN			(change init PIN -> SSO PIN)
					v
			  SSO initialised
					v
				C_InitPIN			(set user PIN)
					v
			  user initialised
					v
				C_Logout
				C_Login				(move from SO -> user state)

		The final logout/login is only needed with some tokens, in others
		the move to user state is automatic once the user PIN is set by the
		SO */
	if( type == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR )
		{
		/* Make sure that there's an SSO PIN present from a previous device
		   initialisation */
		if( strlen( pkcs11Info->defaultSSOPIN ) <= 0 )
			{
			setErrorInfo( deviceInfo, CRYPT_DEVINFO_INITIALISE, 
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}

		/* Change the SSO PIN from the init PIN.  Once we've done this we 
		   clear the initial SSO PIN, since it's no longer valid in the new
		   state */
		status = C_SetPIN( pkcs11Info->hSession, pkcs11Info->defaultSSOPIN,
						   strlen( pkcs11Info->defaultSSOPIN ), 
						   ( CK_CHAR_PTR ) data, ( CK_ULONG ) dataLength );
		zeroise( pkcs11Info->defaultSSOPIN, CRYPT_MAX_TEXTSIZE );
		return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );
		}
	if( type == CRYPT_DEVINFO_SET_AUTHENT_USER )
		{
		status = C_InitPIN( pkcs11Info->hSession, ( CK_CHAR_PTR ) data, 
							( CK_ULONG ) dataLength );
		return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );
		}

	/* Handle initialisation and zeroisation */
	if( type == CRYPT_DEVINFO_INITIALISE || \
		type == CRYPT_DEVINFO_ZEROISE )
		{
		CK_SESSION_HANDLE hSession;
		CK_CHAR label[ 32 ];

		/* If there's a session active with the device, log out and terminate
		   the session, since the token init will reset this */
		if( pkcs11Info->hSession != CRYPT_ERROR )
			{
			C_Logout( pkcs11Info->hSession );
			C_CloseSession( pkcs11Info->hSession );
			pkcs11Info->hSession = CRYPT_ERROR;
			}

		/* Initialise/clear the device, setting the initial SSO PIN */
		memset( label, ' ', 32 );
		status = C_InitToken( pkcs11Info->slotID, 
							  ( CK_CHAR_PTR ) data,
							  ( CK_ULONG ) dataLength, label );
		if( status != CKR_OK )
			return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );

		/* Reopen the session with the device */
		status = C_OpenSession( pkcs11Info->slotID,
								CKF_RW_SESSION | CKF_SERIAL_SESSION,
								NULL_PTR, NULL_PTR, &hSession );
		if( status != CKR_OK )
			return( mapError( pkcs11Info, status, CRYPT_ERROR_OPEN ) );
		pkcs11Info->hSession = hSession;

		/* If it's a straight zeroise, we're done */
		if( type == CRYPT_DEVINFO_ZEROISE )
			return( CRYPT_OK );

		/* We're initialising it, log in as supervisor.  In theory we could 
		   also set the initial user PIN to the same as the SSO PIN at this
		   point because the user usually won't be aware of the presence of
		   an SSO role or the need to set a PIN for it, but this can run into
		   problems with tokens that only allow the user PIN to be modified
		   by the SSO after they've set it for the first time, so if the user
		   *is* aware of the existence of an SSO role then once they log in
		   as SSO they can no longer set the user PIN */
		status = C_Login( pkcs11Info->hSession, CKU_SO,
						  ( CK_CHAR_PTR ) data, ( CK_ULONG ) dataLength );
		if( status != CKR_OK )
			{
			C_Logout( pkcs11Info->hSession );
			C_CloseSession( pkcs11Info->hSession );
			pkcs11Info->hSession = CRYPT_ERROR;
			return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );
			}

		/* Remember the default SSO PIN for use with a future C_SetPIN() */
		memcpy( pkcs11Info->defaultSSOPIN, data, dataLength );
		pkcs11Info->defaultSSOPIN[ dataLength ] = '\0';

		/* We're logged in and ready to go */
		deviceInfo->flags |= DEVICE_LOGGEDIN;
		return( CRYPT_OK );
		}

	/* Handle high-reliability time */
	if( type == CRYPT_IATTRIBUTE_TIME )
		{
		CK_TOKEN_INFO tokenInfo;
		time_t *timePtr = ( time_t * ) data, theTime;

		/* Get the token's time, returned as part of the token info 
		   structure */
		status = C_GetTokenInfo( pkcs11Info->slotID, &tokenInfo );
		if( status != CKR_OK )
			return( mapError( pkcs11Info, status, CRYPT_ERROR_SIGNALLED ) );
		if( ( theTime = getTokenTime( &tokenInfo ) ) < MIN_TIME_VALUE )
			return( CRYPT_ERROR_NOTAVAIL );
		*timePtr = getTime();
		return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_NOTAVAIL );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*						 	Misc.Device Interface Routines					*
*																			*
****************************************************************************/

/* Get random data from the device */

static int getRandomFunction( DEVICE_INFO *deviceInfo, void *buffer,
							  const int length )
	{
	CK_RV status;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;

	status = C_GenerateRandom( pkcs11Info->hSession, buffer, length );
	return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );
	}

/* Get the label for an object.  We can't use a dynBuf for this because it's 
   a PKCS #11 attribute rather than a cryptlib attribute */

static int getObjectLabel( PKCS11_INFO *pkcs11Info, 
						   const CK_OBJECT_HANDLE hObject, 
						   char *label, int *labelLength )
	{
	CK_ATTRIBUTE keyLabelTemplate = \
		{ CKA_LABEL, NULL_PTR, 0 };
	CK_RV status;
	char labelBuffer[ CRYPT_MAX_TEXTSIZE ], *labelPtr = labelBuffer;

	status = C_GetAttributeValue( pkcs11Info->hSession, hObject,
								  &keyLabelTemplate, 1 );
	if( status == CKR_OK )
		{
		if( keyLabelTemplate.ulValueLen > CRYPT_MAX_TEXTSIZE && \
			( labelPtr = clAlloc( "getObjectLabel", \
					( size_t ) ( keyLabelTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		keyLabelTemplate.pValue = labelPtr;
		status = C_GetAttributeValue( pkcs11Info->hSession, hObject,
									  &keyLabelTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		*labelLength = 0;
		if( label != NULL )
			label[ 0 ] = '\0';
		}
	else
		{
		*labelLength = min( keyLabelTemplate.ulValueLen, CRYPT_MAX_TEXTSIZE );
		if( label != NULL )
			memcpy( label, labelPtr, *labelLength );
		}
	if( labelPtr != labelBuffer )
		clFree( "getObjectLabel", labelPtr );
	return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );
	}

/* Instantiate a cert object from a handle */

static int instantiateCert( PKCS11_INFO *pkcs11Info, 
							const CK_OBJECT_HANDLE hCertificate, 
							CRYPT_CERTIFICATE *iCryptCert,
							const BOOLEAN createContext )
	{
	CK_ATTRIBUTE dataTemplate = \
		{ CKA_VALUE, NULL_PTR, 0 };
	CK_RV status;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE buffer[ MAX_BUFFER_SIZE ], *bufPtr = buffer;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* Fetch the cert data into local memory.  We can't use a dynBuf for 
	   this because it's a PKCS #11 attribute rather than a cryptlib 
	   attribute */
	status = C_GetAttributeValue( pkcs11Info->hSession, hCertificate,
								  &dataTemplate, 1 );
	if( status == CKR_OK )
		{
		if( dataTemplate.ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = clAlloc( "instantiateCert", \
					( size_t ) ( dataTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		dataTemplate.pValue = bufPtr;
		status = C_GetAttributeValue( pkcs11Info->hSession, hCertificate,
									  &dataTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			clFree( "instantiateCert", bufPtr );
		return( mapError( pkcs11Info, status, CRYPT_ERROR_NOTFOUND ) );
		}

	/* Import the cert as a cryptlib object */
	setMessageCreateObjectIndirectInfo( &createInfo, bufPtr, 
										dataTemplate.ulValueLen,
										CRYPT_CERTTYPE_CERTIFICATE );
	createInfo.arg1 = createContext ? CRYPT_CERTTYPE_CERTIFICATE : \
									  CERTFORMAT_DATAONLY;
	cryptStatus = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								   IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								   &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( bufPtr != buffer )
		clFree( "instantiateCert", bufPtr );
	if( cryptStatusOK( cryptStatus ) )
		*iCryptCert = createInfo.cryptHandle;
	return( cryptStatus );
	}

/* Find a certificate object based on various search criteria:
   
	- Find cert matching a given label - certFromLabel()
	- Find cert matching a given ID - certFromID()
	- Find cert matching the ID of an object hObject - certFromObject()
	- Find cert matching a supplied template - certFromTemplate()
	- Find any X.509 cert - certFromLabel(), no label supplied.

  These are general-purpose functions whose behaviour can be modified through
  the following action codes */

typedef enum {
	FINDCERT_NORMAL,		/* Instantiate standard cert+context */
	FINDCERT_DATAONLY,		/* Instantiate data-only cert */
	FINDCERT_P11OBJECT		/* Return handle to PKCS #11 object */
	} FINDCERT_ACTION;

static int findCertFromLabel( PKCS11_INFO *pkcs11Info,
							  const char *label, const int labelLength,
							  CRYPT_CERTIFICATE *iCryptCert,
							  const FINDCERT_ACTION findAction )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_LABEL, NULL, 0 }
		};
	CK_OBJECT_HANDLE hCertificate;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* Try and find the cert with the given label */
	if( label != NULL )
		{
		certTemplate[ 2 ].pValue = ( CK_VOID_PTR ) label;
		certTemplate[ 2 ].ulValueLen = labelLength;
		}
	cryptStatus = findObject( pkcs11Info, &hCertificate, certTemplate, 
							  ( label == NULL ) ? 2 : 3 );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	if( findAction == FINDCERT_P11OBJECT )
		{
		*iCryptCert = hCertificate;
		return( CRYPT_OK );
		}

	return( instantiateCert( pkcs11Info, hCertificate, iCryptCert, 
							 ( findAction == FINDCERT_NORMAL ) ? \
							 TRUE : FALSE ) );
	}

static int findCertFromID( PKCS11_INFO *pkcs11Info,
						   const void *certID, 
						   const int certIDlength,
						   CRYPT_CERTIFICATE *iCryptCert,
						   const FINDCERT_ACTION findAction )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ID, ( CK_VOID_PTR ) certID, certIDlength }
		};
	CK_OBJECT_HANDLE hCertificate;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* Try and find the cert with the given ID */
	cryptStatus = findObject( pkcs11Info, &hCertificate, certTemplate, 3 );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	if( findAction == FINDCERT_P11OBJECT )
		{
		*iCryptCert = hCertificate;
		return( CRYPT_OK );
		}

	return( instantiateCert( pkcs11Info, hCertificate, iCryptCert, 
							 ( findAction == FINDCERT_NORMAL ) ? \
							 TRUE : FALSE ) );
	}

static int findCertFromObject( PKCS11_INFO *pkcs11Info,
							   const CK_OBJECT_HANDLE hObject, 
							   CRYPT_CERTIFICATE *iCryptCert,
							   const FINDCERT_ACTION findAction )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ID, NULL, 0 }
		};
	CK_ATTRIBUTE idTemplate = \
		{ CKA_ID, NULL_PTR, 0 };
	CK_RV status;
	BYTE buffer[ MAX_BUFFER_SIZE ], *bufPtr = buffer;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* We're looking for a cert whose ID matches the object, read the key ID 
	   from the device.  We can't use a dynBuf for this because it's a PKCS 
	   #11 attribute rather than a cryptlib attribute */
	status = C_GetAttributeValue( pkcs11Info->hSession, hObject, 
								  &idTemplate, 1 );
	if( status == CKR_OK )
		{
		if( idTemplate.ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = clAlloc( "findCertFromObject", \
						( size_t ) ( idTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		idTemplate.pValue = bufPtr;
		status = C_GetAttributeValue( pkcs11Info->hSession, hObject,
									  &idTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			clFree( "findCertFromObject", bufPtr );
		return( mapError( pkcs11Info, status, CRYPT_ERROR_NOTFOUND ) );
		}

	/* Look for a certificate with the same ID as the key */
	cryptStatus = findCertFromID( pkcs11Info, bufPtr, 
								  idTemplate.ulValueLen, iCryptCert,
								  findAction );
	if( bufPtr != buffer )
		clFree( "findCertFromObject", bufPtr );
	return( cryptStatus );
	}

static int findCertFromTemplate( PKCS11_INFO *pkcs11Info,
								 const CK_ATTRIBUTE *findTemplate,
								 const int templateCount,
								 CRYPT_CERTIFICATE *iCryptCert,
								 const FINDCERT_ACTION findAction )
	{
	CK_OBJECT_HANDLE hCertificate;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* Try and find the cert from the given template */
	cryptStatus = findObject( pkcs11Info, &hCertificate, findTemplate, 
							  templateCount );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	if( findAction == FINDCERT_P11OBJECT )
		{
		*iCryptCert = hCertificate;
		return( CRYPT_OK );
		}

	return( instantiateCert( pkcs11Info, hCertificate, iCryptCert, 
							 ( findAction == FINDCERT_NORMAL ) ? \
							 TRUE : FALSE ) );
	}

/* Find an object from a source object by matching ID's.  This is used to
   find a key matching a cert, a public key matching a private key, or
   other objects with similar relationships */

static int findObjectFromObject( PKCS11_INFO *pkcs11Info,
								 const CK_OBJECT_HANDLE hSourceObject, 
								 const CK_OBJECT_CLASS objectClass,
								 CK_OBJECT_HANDLE *hObject )
	{
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &objectClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_ID, NULL_PTR, 0 }
		};
	CK_ATTRIBUTE idTemplate = \
		{ CKA_ID, NULL_PTR, 0 };
	CK_RV status;
	BYTE buffer[ MAX_BUFFER_SIZE ], *bufPtr = buffer;
	int cryptStatus;

	*hObject = CRYPT_ERROR;

	/* We're looking for a key whose ID matches that of the source object, 
	   read its cert ID.  We can't use a dynBuf for this because it's a 
	   PKCS #11 attribute rather than a cryptlib attribute */
	status = C_GetAttributeValue( pkcs11Info->hSession, hSourceObject, 
								  &idTemplate, 1 );
	if( status == CKR_OK )
		{
		if( idTemplate.ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = clAlloc( "findObjectFromObject", \
						( size_t ) ( idTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		idTemplate.pValue = bufPtr;
		status = C_GetAttributeValue( pkcs11Info->hSession, hSourceObject,
									  &idTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			clFree( "findObjectFromObject", bufPtr );
		return( mapError( pkcs11Info, status, CRYPT_ERROR_NOTFOUND ) );
		}

	/* Find the key object with the given ID */
	keyTemplate[ 1 ].pValue = bufPtr;
	keyTemplate[ 1 ].ulValueLen = idTemplate.ulValueLen;
	cryptStatus = findObject( pkcs11Info, hObject, keyTemplate, 2 );
	if( bufPtr != buffer )
		clFree( "findObjectFromObject", bufPtr );
	return( cryptStatus );
	}

/* Read a flag for an object.  An absent value is treated as FALSE */

static BOOLEAN readFlag( PKCS11_INFO *pkcs11Info, 
						 const CK_OBJECT_HANDLE hObject,
						 const CK_ATTRIBUTE_TYPE flagType )
	{
	CK_BBOOL bFlag = FALSE;
	CK_ATTRIBUTE flagTemplate = { flagType, &bFlag, sizeof( CK_BBOOL ) };

	/* Some buggy implementations return CKR_OK but forget to set the
	   data value in the template (!!!) so we have to initialise bFlag
	   to a default of FALSE to handle this */
	return( ( C_GetAttributeValue( pkcs11Info->hSession, hObject,
								   &flagTemplate, 1 ) == CKR_OK && bFlag ) ? \
			TRUE : FALSE );
	}
		
/* Instantiate an object in a device.  This works like the create context
   function but instantiates a cryptlib object using data already contained
   in the device (for example a stored private key or certificate).  If the
   value being read is a public key and there's a certificate attached, the
   instantiated object is a native cryptlib object rather than a device
   object with a native certificate object attached because there doesn't 
   appear to be any good reason to create the public-key object in the device, 
   for most devices the cryptlib native object will be faster anyway, and 
   some apps see the public key as redundant and delete it, so only the cert
   will be present */

static int rsaSetPublicComponents( PKCS11_INFO *pkcs11Info,
								   const CRYPT_CONTEXT iCryptContext,
								   const CK_OBJECT_HANDLE hRsaKey );

static int getItemFunction( DEVICE_INFO *deviceInfo,
							CRYPT_CONTEXT *iCryptContext,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID, const int keyIDlength,
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	const CAPABILITY_INFO *capabilityInfoPtr;
	CK_ATTRIBUTE iAndSTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ISSUER, NULL_PTR, 0 },
		{ CKA_SERIAL_NUMBER, NULL_PTR, 0 }
		}, iAndSTemplateAlt[ 4 ];
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, NULL_PTR, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, NULL_PTR, 0 }
		};
	CK_ATTRIBUTE keyTypeTemplate = \
		{ CKA_KEY_TYPE, NULL_PTR, sizeof( CK_KEY_TYPE ) };
	CK_ATTRIBUTE keySizeTemplate = \
		{ 0, NULL_PTR, 0 };
	CK_ATTRIBUTE keyLabelTemplate = \
		{ CKA_LABEL, NULL_PTR, 0 };
	CK_OBJECT_HANDLE hObject, hCertificate;
	CK_KEY_TYPE keyType;
	CRYPT_CERTIFICATE iCryptCert;
	CRYPT_ALGO_TYPE cryptAlgo;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	RESOURCE_DATA msgData;
	BOOLEAN certViaPrivateKey = FALSE, privateKeyViaCert = FALSE;
	BOOLEAN certPresent = FALSE;
	BOOLEAN cryptAllowed = FALSE, sigAllowed = FALSE;
	char label[ CRYPT_MAX_TEXTSIZE ];
	int keySize, actionFlags = 0, labelLength, cryptStatus;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );

	/* If we're looking for something based on an issuerAndSerialNumber, set 
	   up the search template.  Because Netscape incorrectly uses the raw
	   serial number and other apps copy this, we also set up an alternative 
	   template with the serial number in this alternative form that we fall 
	   back to if a search using the correct form fails */
	if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
		{
		STREAM stream;
		int length;

		sMemConnect( &stream, keyID, keyIDlength );
		readSequence( &stream, NULL );
		iAndSTemplate[ 2 ].pValue = sMemBufPtr( &stream );
		readSequence( &stream, &length );		/* Issuer DN */
		iAndSTemplate[ 2 ].ulValueLen = ( int ) sizeofObject( length );
		sSkip( &stream, length );
		iAndSTemplate[ 3 ].pValue = sMemBufPtr( &stream );
		readGenericHole( &stream, &length, BER_INTEGER );/* Serial number */
		iAndSTemplate[ 3 ].ulValueLen = ( int ) sizeofObject( length );
		memcpy( iAndSTemplateAlt, iAndSTemplate, sizeof( iAndSTemplate ) );
		iAndSTemplateAlt[ 3 ].pValue = sMemBufPtr( &stream );
		iAndSTemplateAlt[ 3 ].ulValueLen = length;
		assert( sStatusOK( &stream ) );
		sMemDisconnect( &stream );
		}

	/* If we're looking for a public key, try for a cert first.  Some non-
	   crypto-capable devices don't have an explicit CKO_PUBLIC_KEY but only 
	   a CKO_CERTIFICATE and some apps delete the public key since it's
	   redundant, so we try to create a cert object before we try anything 
	   else.  If the keyID type is an ID or label, this won't necessarily 
	   locate the cert since it could be unlabelled or have a different 
	   label/ID, so if this fails we try again by going via the private key 
	   with the given label/ID */
	if( itemType == KEYMGMT_ITEM_PUBLICKEY )
		{
		const FINDCERT_ACTION findAction = \
			( flags & ( KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_LABEL_ONLY ) ) ? \
			FINDCERT_P11OBJECT : FINDCERT_NORMAL;

		if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
			{
			cryptStatus = findCertFromTemplate( pkcs11Info, iAndSTemplate, 4, 
												&iCryptCert, findAction );
			if( cryptStatus == CRYPT_ERROR_NOTFOUND )
				cryptStatus = findCertFromTemplate( pkcs11Info, iAndSTemplateAlt, 4, 
													&iCryptCert, findAction );
			}
		else
			if( keyIDtype == CRYPT_IKEYID_KEYID )
				cryptStatus = findCertFromID( pkcs11Info, keyID, keyIDlength, 
											  &iCryptCert, findAction );
			else
				{
				cryptStatus = findCertFromLabel( pkcs11Info, keyID, keyIDlength, 
												 &iCryptCert, findAction );
				if( cryptStatus == CRYPT_ERROR_NOTFOUND )
					/* Some devices use the iD in place of the label, if a 
					   search by label fails we try again with the label as 
					   the iD */
					cryptStatus = findCertFromID( pkcs11Info, keyID, keyIDlength, 
												  &iCryptCert, findAction );
				}
		if( cryptStatusOK( cryptStatus ) )
			{
			/* If we're just checking whether an object exists, return now.  
			   If all we want is the key label, copy it back to the caller 
			   and exit */
			if( flags & KEYMGMT_FLAG_CHECK_ONLY )
				return( CRYPT_OK );
			if( flags & KEYMGMT_FLAG_LABEL_ONLY )
				return( getObjectLabel( pkcs11Info, 
										( CK_OBJECT_HANDLE ) iCryptCert, 
										auxInfo, auxInfoLength ) );

			*iCryptContext = iCryptCert;
			return( CRYPT_OK );
			}
		else
			/* If we're looking for a specific match on a certificate (rather 
			   than just a general public key) and we don't find anything, 
			   exit now */
			if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
				return( cryptStatus );
		}

	/* Either there were no certs found or we're looking for a private key 
	   (or, somewhat unusually, a raw public key).  At this point we can 
	   approach the problem from one of two sides, if we've got an 
	   issuerAndSerialNumber we have to find the matching cert and get the 
	   key from that, otherwise we find the key and get the cert from that */
	if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
		{
		/* Try and find the cert from the given template */
		cryptStatus = findObject( pkcs11Info, &hCertificate, 
								  iAndSTemplate, 4 );
		if( cryptStatus == CRYPT_ERROR_NOTFOUND )
			cryptStatus = findObject( pkcs11Info, &hCertificate, 
									  iAndSTemplateAlt, 4 );
		if( cryptStatusOK( cryptStatus ) )
			{
			/* We found the cert, use it to find the corresponding private 
			   key */
			cryptStatus = findObjectFromObject( pkcs11Info, hCertificate, 
												CKO_PRIVATE_KEY, &hObject );
			if( cryptStatusError( cryptStatus ) )
				return( cryptStatus );
	
			/* Remember that we've already got a cert to attach to the private
			   key */
			privateKeyViaCert = TRUE;
			}
		else
			/* If we didn't find anything, it may be because whoever set up
			   the token didn't set the iAndS rather than because there's no
			   key there, so we only bail out if we got some unexpected type 
			   of error */
			if( cryptStatus != CRYPT_ERROR_NOTFOUND )
				return( cryptStatus );
		}
	else
		{
		const int keyTemplateCount = ( keyID == NULL ) ? 1 : 2;

		/* Try and find the object with the given label/ID, or the first 
		   object of the given class if no ID is given */
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) \
								  ( ( itemType == KEYMGMT_ITEM_PUBLICKEY ) ? \
								  &pubkeyClass : &privkeyClass );
		if( keyIDtype != CRYPT_KEYID_NONE )
			{
			if( keyIDtype == CRYPT_IKEYID_KEYID )
				keyTemplate[ 1 ].type = CKA_ID;
			keyTemplate[ 1 ].pValue = ( CK_VOID_PTR ) keyID;
			keyTemplate[ 1 ].ulValueLen = keyIDlength;
			}
		cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 
								  keyTemplateCount );
		if( cryptStatus == CRYPT_ERROR_NOTFOUND )
			{
			/* Some devices use the iD in place of the label, if a search by 
			   label fails we try again with the label as the iD */
			keyTemplate[ 1 ].type = CKA_ID;
			cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 
									  keyTemplateCount );
			keyTemplate[ 1 ].type = CKA_LABEL;
			}
		if( cryptStatus == CRYPT_ERROR_NOTFOUND && \
			itemType == KEYMGMT_ITEM_PUBLICKEY )
			{
			/* Some devices may only contain private key objects with 
			   associated certificates that can't be picked out of the other 
			   cruft that's present without going via the private key, so if 
			   we're looking for a public key and don't find one, we try 
			   again for a private key whose sole function is to point to an 
			   associated cert */
			keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &privkeyClass;
			cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 
									  keyTemplateCount );
			if( cryptStatusError( cryptStatus ) )
				return( cryptStatus );
		
			/* Remember that although we've got a private key object, we only 
			   need it to find the associated cert and not finding an 
			   associated cert is an error */
			certViaPrivateKey = TRUE;
			}
		}

	/* If we're looking for any kind of private key and we either have an
	   explicit cert.ID but couldn't find a cert for it or we don't have a 
	   proper ID to search on and a generic search found more than one 
	   matching object, chances are we're after a generic decrypt key.  The 
	   former only occurs in misconfigured or limited-memory tokens, the 
	   latter only in rare tokens that store more than one private key, 
	   typically one for signing and one for verification.  
	   
	   If either of these cases occur we try again looking specifically for 
	   a decryption key.  Even this doesn't always work, there's are some
	   >1-key tokens that mark a signing key as a decryption key so we still 
	   get a CRYPT_ERROR_DUPLICATE error.
	   
	   Finally, if we can't find a decryption key either, we look for an
	   unwrapping key.  This may or may not work, depending on whether we 
	   have a decryption key marked as valid for unwrapping but not 
	   decryption, or a key that's genuinely only valid for unwrapping, but
	   at this point we're ready to try anything */
	if( itemType == KEYMGMT_ITEM_PRIVATEKEY && \
		( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER && \
		  cryptStatus == CRYPT_ERROR_NOTFOUND ) || \
		( cryptStatus == CRYPT_ERROR_DUPLICATE ) )
		{
		static const CK_BBOOL bTrue = TRUE;
		CK_ATTRIBUTE decryptKeyTemplate[] = {
			{ CKA_CLASS, ( CK_VOID_PTR ) &privkeyClass, sizeof( CK_OBJECT_CLASS ) },
			{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) }
			};

		cryptStatus = findObject( pkcs11Info, &hObject, 
								  decryptKeyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			{
			decryptKeyTemplate[ 1 ].type = CKA_UNWRAP;
			cryptStatus = findObject( pkcs11Info, &hObject, 
									  decryptKeyTemplate, 2 );
			}
		}
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* If we're just checking whether an object exists, return now.  If all 
	   we want is the key label, copy it back to the caller and exit */
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		return( CRYPT_OK );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		return( getObjectLabel( pkcs11Info, hObject, auxInfo, 
								auxInfoLength ) );

	/* We found something, map the key type to a cryptlib algorithm ID,
	   determine the key size, and find its capabilities */
	keyTypeTemplate.pValue = &keyType;
	C_GetAttributeValue( pkcs11Info->hSession, hObject, 
						 &keyTypeTemplate, 1 );
	switch( ( int ) keyType )
		{
		case CKK_RSA:
			cryptAlgo = CRYPT_ALGO_RSA;
			keySizeTemplate.type = CKA_MODULUS;
			break;
		case CKK_DSA:
			cryptAlgo = CRYPT_ALGO_DSA;
			keySizeTemplate.type = CKA_PRIME;
			break;
		case CKK_DH:
			cryptAlgo = CRYPT_ALGO_DH;
			keySizeTemplate.type = CKA_PRIME;
			break;
		default:
			return( CRYPT_ERROR_NOTAVAIL );
		}
	C_GetAttributeValue( pkcs11Info->hSession, hObject, 
						 &keySizeTemplate, 1 );
	keySize = keySizeTemplate.ulValueLen;
	capabilityInfoPtr = findCapabilityInfo( deviceInfo->capabilityInfo, 
											cryptAlgo );
	if( capabilityInfoPtr == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Try and find a certificate which matches the key.  The process is as
	   follows:

		if cert object found in issuerAndSerialNumber search
			create native data-only cert object
			attach cert object to key
		else
			if public key
				if cert
					create native cert (+context) object
				else
					create device pubkey object, mark as "key loaded"
			else
				create device privkey object, mark as "key loaded"
				if cert
					create native data-only cert object
					attach cert object to key

	   The reason for doing things this way is given in the comments earlier
	   on in this function */
	if( privateKeyViaCert )
		{
		/* We've already got the cert object handle, instantiate a native
		   data-only cert from it */
		cryptStatus = instantiateCert( pkcs11Info, hCertificate, 
									   &iCryptCert, FALSE );
		if( cryptStatusError( cryptStatus ) )
			return( cryptStatus );
		certPresent = TRUE;
		}
	else
		{
		cryptStatus = findCertFromObject( pkcs11Info, hObject, &iCryptCert, 
										  ( itemType == KEYMGMT_ITEM_PUBLICKEY ) ? \
										  FINDCERT_NORMAL : FINDCERT_DATAONLY );
		if( cryptStatusError( cryptStatus ) )
			{
			/* If we get a CRYPT_ERROR_NOTFOUND this is OK since it means 
			   there's no cert present, however anything else is an error. In 
			   addition if we've got a private key whose only function is to 
			   point to an associated cert then not finding anything is also 
			   an error */
			if( cryptStatus != CRYPT_ERROR_NOTFOUND || certViaPrivateKey )
				return( cryptStatus );
			}
		else
			{
			/* We got the cert, if we're being asked for a public key then
			   we've created a native object to contain it so we return that */
			certPresent = TRUE;
			if( itemType == KEYMGMT_ITEM_PUBLICKEY )
				{
				*iCryptContext = iCryptCert;
				return( CRYPT_OK );
				}
			}
		}

	/* Get the permitted capabilities for the object */
	if( readFlag( pkcs11Info, hObject, CKA_ENCRYPT ) || \
		readFlag( pkcs11Info, hObject, CKA_UNWRAP ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL );
		cryptAllowed = TRUE;
		}
	if( readFlag( pkcs11Info, hObject, CKA_DECRYPT ) || \
		readFlag( pkcs11Info, hObject, CKA_UNWRAP ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
		cryptAllowed = TRUE;
		}
	if( readFlag( pkcs11Info, hObject, CKA_SIGN ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
		sigAllowed = TRUE;
		}
	if( readFlag( pkcs11Info, hObject, CKA_VERIFY ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL );
		sigAllowed = TRUE;
		}
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		/* If there are any restrictions on the key usage, we have to make it
		   internal-only because of RSA's signature/encryption duality */
		if( !( cryptAllowed && sigAllowed ) )
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
		}
	else
		/* Because of the special-case data formatting requirements for DLP 
		   algorithms, we make the usage internal-only */
		actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
	if( !actionFlags )
		{
		/* If no usage is allowed, we can't do anything with the object so
		   we don't even try to create it */
		if( certPresent )
			krnlSendNotifier( iCryptCert, IMESSAGE_DECREFCOUNT );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Create a dummy context for the key, remember the device it's 
	   contained in, the handle for the device-internal key, and the object's
	   label, mark it as initialised (i.e. with a key loaded), and if there's a 
	   cert present attach it to the context.  The cert is an internal object 
	   used only by the context so we tell the kernel to mark it as owned by 
	   the context only */
	cryptStatus = getObjectLabel( pkcs11Info, hObject, label, &labelLength );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = createContextFromCapability( iCryptContext, 
								deviceInfo->ownerHandle, capabilityInfoPtr, 
								CREATEOBJECT_FLAG_DUMMY );
	if( cryptStatusError( cryptStatus ) )
		{
		if( certPresent )
			krnlSendNotifier( iCryptCert, IMESSAGE_DECREFCOUNT );
		return( cryptStatus );
		}
	krnlSendMessage( *iCryptContext, IMESSAGE_SETDEPENDENT,
					 &deviceInfo->objectHandle, SETDEP_OPTION_INCREF );
	krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE, &hObject, 
					 CRYPT_IATTRIBUTE_DEVICEOBJECT );
	krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE, &actionFlags, 
					 CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( labelLength <= 0 )
		{
		/* If there's no label present, use a dummy value */
		strcpy( label, "Label-less PKCS #11 key" );
		labelLength = strlen( label );
		}
	setMessageData( &msgData, label, labelLength );
	krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_LABEL );
	if( keyType == CKK_RSA )
		/* Send the keying info to the context.  This is only possible for
		   RSA keys since it's not possible to read y from a DSA private
		   key object (see the comments in the DSA code for more on this), 
		   however the only time this is necessary is when a cert is being 
		   generated for a key that was pre-generated in the device by 
		   someone else, which is typically done in Europe where DSA isn't 
		   used so this shouldn't be a problem */
		cryptStatus = rsaSetPublicComponents( pkcs11Info, *iCryptContext, 
											  hObject );
	else
		cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE, 
									   &keySize, CRYPT_IATTRIBUTE_KEYSIZE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE,
									   MESSAGE_VALUE_UNUSED, 
									   CRYPT_IATTRIBUTE_INITIALISED );
	if( certPresent && cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETDEPENDENT, 
									   &iCryptCert, SETDEP_OPTION_NOINCREF );
	if( cryptStatusError( cryptStatus ) && certPresent )
		krnlSendNotifier( iCryptCert, IMESSAGE_DECREFCOUNT );
	return( cryptStatus );
	}

/* Update a device with a certificate */

static int setItemFunction( DEVICE_INFO *deviceInfo, 
							const CRYPT_HANDLE iCryptHandle )
	{
	CRYPT_CERTIFICATE iCryptCert;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	int cryptStatus;

	/* Lock the cert for our exclusive use (in case it's a cert chain, we 
	   also select the first cert in the chain), update the device with the 
	   cert, and unlock it to allow others access */
	krnlSendMessage( iCryptHandle, IMESSAGE_GETDEPENDENT, &iCryptCert, 
					 OBJECT_TYPE_CERTIFICATE );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORFIRST, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	cryptStatus = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
								   MESSAGE_VALUE_TRUE, 
								   CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	cryptStatus = updateCertificate( pkcs11Info, iCryptCert );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_FALSE, 
					 CRYPT_IATTRIBUTE_LOCKED );

	return( cryptStatus );
	}

/* Delete an object in a device */

static int deleteItemFunction( DEVICE_INFO *deviceInfo,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_LABEL, ( CK_VOID_PTR ) keyID, keyIDlength }
		};
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &pubkeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, ( CK_VOID_PTR ) keyID, keyIDlength }
		};
	CK_OBJECT_HANDLE hPrivkey = CRYPT_ERROR, hCertificate = CRYPT_ERROR;
	CK_OBJECT_HANDLE hPubkey = CRYPT_ERROR;
	CK_RV status;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	int cryptStatus;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME );

	/* Find the object to delete based on the label.  Since we can have 
	   multiple related objects (e.g. a key and a cert) with the same label, 
	   a straight search for all objects with a given label could return
	   CRYPT_ERROR_DUPLICATE so we search for the objects by type as well as 
	   label.  In addition even a search for specific objects can return
	   CRYPT_ERROR_DUPLICATE so we use the Ex version of findObject() to make
	   sure we don't get an error if multiple objects exist.  Although
	   cryptlib won't allow more than one object with a given label to be
	   created, other applications might create duplicate labels.  The correct
	   behaviour in these circumstances is uncertain, what we do for now is
	   delete the first object we find that matches the label.
	   
	   First we try for a cert and use that to find associated keys */
	cryptStatus = findObjectEx( pkcs11Info, &hCertificate, certTemplate, 3 );
	if( cryptStatusOK( cryptStatus ) )
		{
		/* We got a cert, if there are associated keys delete them as well */
		cryptStatus = findObjectFromObject( pkcs11Info, hCertificate, 
											CKO_PUBLIC_KEY, &hPubkey );
		if( cryptStatusError( cryptStatus ) )
			hPubkey = CRYPT_ERROR;
		cryptStatus = findObjectFromObject( pkcs11Info, hCertificate, 
											CKO_PRIVATE_KEY, &hPrivkey );
		if( cryptStatusError( cryptStatus ) )
			hPrivkey = CRYPT_ERROR;
		}
	else
		{
		/* We didn't find a cert with the given label, try for public and
		   private keys */
		cryptStatus = findObjectEx( pkcs11Info, &hPubkey, keyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			hPubkey = CRYPT_ERROR;
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &privkeyClass;
		cryptStatus = findObjectEx( pkcs11Info, &hPrivkey, keyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			hPrivkey = CRYPT_ERROR;

		/* There may be an unlabelled cert present, try and find it by 
		   looking for a cert matching the key ID */
		if( hPubkey != CRYPT_ERROR || hPrivkey != CRYPT_ERROR )
			{
			cryptStatus = findObjectFromObject( pkcs11Info, 
							( hPrivkey != CRYPT_ERROR ) ? hPrivkey : hPubkey, 
							CKO_CERTIFICATE, &hCertificate );
			if( cryptStatusError( cryptStatus ) )
				hCertificate = CRYPT_ERROR;
			}
		}

	/* If we found a public key with a given label but no private key, try 
	   and find a matching private key by ID, and vice versa */
	if( hPubkey != CRYPT_ERROR && hPrivkey == CRYPT_ERROR )
		{
		cryptStatus = findObjectFromObject( pkcs11Info, hPubkey, 
											CKO_PRIVATE_KEY, &hPrivkey );
		if( cryptStatusError( cryptStatus ) )
			hPrivkey = CRYPT_ERROR;
		}
	if( hPrivkey != CRYPT_ERROR && hPubkey == CRYPT_ERROR )
		{
		cryptStatus = findObjectFromObject( pkcs11Info, hPrivkey, 
											CKO_PUBLIC_KEY, &hPubkey );
		if( cryptStatusError( cryptStatus ) )
			hPubkey = CRYPT_ERROR;
		}
	if( hPrivkey == CRYPT_ERROR && hPubkey == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Reset the status values, which may contain error values due to not 
	   finding various objects to delete above */
	cryptStatus = CRYPT_OK;
	status = CKR_OK;

	/* Delete the objects */
	if( hCertificate != CRYPT_ERROR )
		status = C_DestroyObject( pkcs11Info->hSession, hCertificate );
	if( hPubkey != CRYPT_ERROR )
		{
		int status2;

		status2 = C_DestroyObject( pkcs11Info->hSession, hPubkey );
		if( status2 != CKR_OK && status == CKR_OK )
			status = status2;
		}
	if( hPrivkey != CRYPT_ERROR )
		{
		int status2;

		status2 = C_DestroyObject( pkcs11Info->hSession, hPrivkey );
		if( status2 != CKR_OK && status == CKR_OK )
			status = status2;
		}
	if( status != CKR_OK )
		cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );
	return( cryptStatus );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

/* Sign data, check a signature.  We use Sign and Verify rather than the
   xxxRecover variants because there's no need to use Recover, and because
   many implementations don't do Recover */

static int genericSign( PKCS11_INFO *pkcs11Info, 
						CONTEXT_INFO *contextInfoPtr,
						const CK_MECHANISM *pMechanism, 
						const void *inBuffer, const int inLength, 
						void *outBuffer, const int outLength )
	{
	CK_ULONG resultLen = outLength;
	CK_RV status;

	status = C_SignInit( pkcs11Info->hSession,
						 ( CK_MECHANISM_PTR ) pMechanism, 
						 contextInfoPtr->deviceObject );
	if( status == CKR_OK )
		status = C_Sign( pkcs11Info->hSession, ( CK_BYTE_PTR ) inBuffer, 
						 inLength, outBuffer, &resultLen );
	if( status != CKR_OK )
		return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );

	return( CRYPT_OK );
	}

static int genericVerify( PKCS11_INFO *pkcs11Info, 
						  CONTEXT_INFO *contextInfoPtr,
						  const CK_MECHANISM *pMechanism, 
						  const void *inBuffer, const int inLength, 
						  void *outBuffer, const int outLength )
	{
	CK_RV status;

	status = C_VerifyInit( pkcs11Info->hSession,
						   ( CK_MECHANISM_PTR ) pMechanism,
						   contextInfoPtr->deviceObject );
	if( status == CKR_OK )
		status = C_Verify( pkcs11Info->hSession, ( CK_BYTE_PTR ) inBuffer, 
						   inLength, outBuffer, outLength );
	if( status != CKR_OK )
		return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );

	return( CRYPT_OK );
	}

/* Encrypt, decrypt */

static int genericEncrypt( PKCS11_INFO *pkcs11Info, 
						   CONTEXT_INFO *contextInfoPtr,
						   const CK_MECHANISM *pMechanism, void *buffer,
						   const int length, const int outLength )
	{
	CK_ULONG resultLen = outLength;
	CK_RV status;

	status = C_EncryptInit( pkcs11Info->hSession,
							( CK_MECHANISM_PTR ) pMechanism,
							contextInfoPtr->deviceObject );
	if( status == CKR_OK )
		status = C_Encrypt( pkcs11Info->hSession, buffer, length,
							buffer, &resultLen );
	if( status != CKR_OK )
		return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );

	/* When performing RSA operations some buggy implementations perform 
	   leading-zero trunction, so we restore leading zeroes if necessary */
	if( ( pMechanism->mechanism == CKM_RSA_X_509 || \
		  pMechanism->mechanism == CKM_RSA_PKCS ) && \
		( int ) resultLen < length )
		{
		const int delta = length - resultLen;

		memmove( ( BYTE * ) buffer + delta, buffer, resultLen );
		memset( buffer, 0, delta );
		}

	return( CRYPT_OK );
	}

static int genericDecrypt( PKCS11_INFO *pkcs11Info, 
						   CONTEXT_INFO *contextInfoPtr,
						   const CK_MECHANISM *pMechanism, void *buffer,
						   const int length, int *resultLength )
	{
	CK_ULONG resultLen = length;
	CK_RV status;

	status = C_DecryptInit( pkcs11Info->hSession,
							( CK_MECHANISM_PTR ) pMechanism,
							contextInfoPtr->deviceObject );
	if( status == CKR_OK )
		status = C_Decrypt( pkcs11Info->hSession, buffer, length,
							buffer, &resultLen );
	if( status == CKR_KEY_FUNCTION_NOT_PERMITTED )
		{
		static const CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
		static const CK_KEY_TYPE secretKeyType = CKK_GENERIC_SECRET;
		CK_ATTRIBUTE asymTemplate[] = { 
			{ CKA_CLASS, ( CK_VOID_PTR ) &secretKeyClass, sizeof( CK_OBJECT_CLASS ) },
			{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &secretKeyType, sizeof( CK_KEY_TYPE ) },
			{ CKA_VALUE_LEN, &resultLen, sizeof( CK_ULONG ) } 
			};
		CK_ATTRIBUTE symTemplate[] = { CKA_VALUE, buffer, length };
		CK_OBJECT_HANDLE symKey;

		/* If a straight decrypt isn't allowed, try an unwrap instead and 
		   then export the key.  This works because we're using the same
		   mechanism as for decrypt and converting the entire "unwrapped key"
		   into a generic secret key that we then extract, which is the
		   same as doing a straight decrypt of the data (this sort of thing
		   should require a note from your mother before you're allowed to do
		   it).  The reason why it's done in this roundabout manner is that 
		   this is what Netscape tries first, so people doing a minimal 
		   implementation do this first and don't bother with anything else.  
		   Note that doing it this way is rather slower than a straight 
		   decrypt, which is why we try for decrypt first */
		status = C_UnwrapKey( pkcs11Info->hSession,
							  ( CK_MECHANISM_PTR ) pMechanism,
							  contextInfoPtr->deviceObject, buffer, length,
							  asymTemplate, 3, &symKey );
		if( status == CKR_OK )
			status = C_GetAttributeValue( pkcs11Info->hSession, 
										  symKey, symTemplate, 1 );
		if( status == CKR_OK )
			resultLen = symTemplate[ 0 ].ulValueLen;
		}
	if( status != CKR_OK )
		return( mapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );

	/* When performing raw RSA operations some buggy implementations perform 
	   leading-zero trunction, so we restore leading zeroes if necessary.  We
	   can't do the restore with the PKCS mechanism since it always returns a 
	   result length shorter than the input length */
	if( pMechanism->mechanism == CKM_RSA_X_509 && \
		( int ) resultLen < length )
		{
		const int delta = length - resultLen;

		memmove( ( BYTE * ) buffer + delta, buffer, resultLen );
		memset( buffer, 0, delta );
		resultLen = length;
		}

	/* Some mechanisms change the data length, in which case we need to tell
	   the caller how much was actually returned */
	if( resultLength != NULL )
		*resultLength = ( int ) resultLen;
	return( CRYPT_OK );
	}

/* Clean up the object associated with a context */

static int genericEndFunction( CONTEXT_INFO *contextInfoPtr )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	PKCS11_INFO *pkcs11Info;
	int cryptStatus;

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	pkcs11Info = deviceInfo->devicePKCS11;

	/* Destroy the object */
	C_DestroyObject( pkcs11Info->hSession, contextInfoPtr->deviceObject );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( CRYPT_OK );
	}

/* RSA algorithm-specific mapping functions.  Externally we always appear to 
   use the X.509 (raw) mechanism for the encrypt/decrypt/sign/verify 
   functions since cryptlib does its own padding (with workarounds for 
   various bugs and peculiarities).  Internally however we have to use the
   PKCS mechanism since some implementations don't support the X.509
   mechanism, and add/remove the padding to fake out the presence of a raw
   RSA mechanism */

static int rsaSetPublicComponents( PKCS11_INFO *pkcs11Info,
								   const CRYPT_CONTEXT iCryptContext,
								   const CK_OBJECT_HANDLE hRsaKey )
	{
	CK_ATTRIBUTE nTemplate = { CKA_MODULUS, NULL_PTR, CRYPT_MAX_PKCSIZE };
	CK_ATTRIBUTE eTemplate = { CKA_PUBLIC_EXPONENT, NULL_PTR, CRYPT_MAX_PKCSIZE };
	CK_RV status;
	BYTE n[ CRYPT_MAX_PKCSIZE ], e[ CRYPT_MAX_PKCSIZE ];
	BYTE keyDataBuffer[ CRYPT_MAX_PKCSIZE * 2 ];
	RESOURCE_DATA msgData;
	int keyDataSize, cryptStatus;

	/* Get the public key components from the device.  The odd two-phase 
	   read is necessary for buggy implementations that fail if the given 
	   size isn't exactly the same as the data size */
	status = C_GetAttributeValue( pkcs11Info->hSession, hRsaKey, 
								  &nTemplate, 1 );
	if( status == CKR_OK )
		{
		nTemplate.pValue = n;
		status = C_GetAttributeValue( pkcs11Info->hSession, hRsaKey, 
									  &nTemplate, 1 );
		}
	cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	status = C_GetAttributeValue( pkcs11Info->hSession, hRsaKey, 
								  &eTemplate, 1 );
	if( status == CKR_OK )
		{
		eTemplate.pValue = e;
		status = C_GetAttributeValue( pkcs11Info->hSession, hRsaKey, 
									  &eTemplate, 1 );
		}
	cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* Send the public key data to the context.  We send the keying info as
	   CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL rather than CRYPT_IATTRIBUTE_KEY_SPKI
	   since the latter transitions the context into the high state.  We 
	   don't want to do this because we're already in the middle of processing
	   a message that does this on completion, all we're doing here is 
	   sending in encoded public key data for use by objects such as 
	   certificates */
	cryptStatus = keyDataSize = writeFlatPublicKey( NULL, 0, CRYPT_ALGO_RSA, 
							n, nTemplate.ulValueLen, e, eTemplate.ulValueLen, 
							NULL, 0, NULL, 0 );
	if( !cryptStatusError( cryptStatus ) )
		cryptStatus = writeFlatPublicKey( keyDataBuffer, CRYPT_MAX_PKCSIZE * 2,
							CRYPT_ALGO_RSA, n, nTemplate.ulValueLen, 
							e, eTemplate.ulValueLen, NULL, 0, NULL, 0 );
	if( cryptStatusOK( cryptStatus ) )
		krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, 
						 ( void * ) &nTemplate.ulValueLen, 
						 CRYPT_IATTRIBUTE_KEYSIZE );
	if( cryptStatusOK( cryptStatus ) )
		{
		setMessageData( &msgData, keyDataBuffer, keyDataSize );
		cryptStatus = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
									   &msgData, 
									   CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL );
		}
	return( cryptStatus );
	}

static int rsaSetKeyInfo( PKCS11_INFO *pkcs11Info,
						  CONTEXT_INFO *contextInfoPtr, 
						  const CK_OBJECT_HANDLE hPrivateKey,
						  const CK_OBJECT_HANDLE hPublicKey )
	{
	RESOURCE_DATA msgData;
	BYTE idBuffer[ KEYID_SIZE ];
	int cryptStatus;

	/* Remember what we've set up */
	krnlSendMessage( contextInfoPtr->objectHandle, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &hPrivateKey, CRYPT_IATTRIBUTE_DEVICEOBJECT );

	/* Get the key ID from the context and use it as the object ID.  Since 
	   some objects won't allow after-the-event ID updates, we don't treat a
	   failure to update as an error */
	setMessageData( &msgData, idBuffer, KEYID_SIZE );
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETATTRIBUTE_S, &msgData, 
								   CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusOK( cryptStatus ) )
		{
		CK_ATTRIBUTE idTemplate = { CKA_ID, msgData.data, msgData.length };

		if( hPublicKey != CRYPT_UNUSED )
			C_SetAttributeValue( pkcs11Info->hSession, hPublicKey, 
								 &idTemplate, 1 );
		C_SetAttributeValue( pkcs11Info->hSession, hPrivateKey, 
							 &idTemplate, 1 );
		}
	
	return( cryptStatus );
	}

static int rsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					   const int keyLength )
	{
	static const CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	static const CK_KEY_TYPE type = CKK_RSA;
	static const CK_BBOOL bTrue = TRUE;
	CK_ATTRIBUTE rsaKeyTemplate[] = {
		/* Shared fields */
		{ CKA_CLASS, ( CK_VOID_PTR ) &privKeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &type, sizeof( CK_KEY_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, contextInfoPtr->label, contextInfoPtr->labelSize },
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 },
		/* Private-key only fields */
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE_EXPONENT, NULL, 0 },
		{ CKA_PRIME_1, NULL, 0 },
		{ CKA_PRIME_2, NULL, 0 },
		{ CKA_EXPONENT_1, NULL, 0 },
		{ CKA_EXPONENT_2, NULL, 0 },
		{ CKA_COEFFICIENT, NULL, 0 },
		};
	CRYPT_PKCINFO_RSA *rsaKey = ( CRYPT_PKCINFO_RSA * ) key;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	PKCS11_INFO *pkcs11Info;
	CK_OBJECT_HANDLE hRsaKey;
	CK_RV status;
	const int templateCount = rsaKey->isPublicKey ? 8 : 15;
	int cryptStatus;

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	pkcs11Info = deviceInfo->devicePKCS11;
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Set up the key values */
	rsaKeyTemplate[ 6 ].pValue = rsaKey->n;
	rsaKeyTemplate[ 6 ].ulValueLen = bitsToBytes( rsaKey->nLen );
	rsaKeyTemplate[ 7 ].pValue = rsaKey->e;
	rsaKeyTemplate[ 7 ].ulValueLen = bitsToBytes( rsaKey->eLen );
	if( !rsaKey->isPublicKey )
		{
		rsaKeyTemplate[ 9 ].pValue = rsaKey->d;
		rsaKeyTemplate[ 9 ].ulValueLen = bitsToBytes( rsaKey->dLen );
		rsaKeyTemplate[ 10 ].pValue = rsaKey->p;
		rsaKeyTemplate[ 10 ].ulValueLen = bitsToBytes( rsaKey->pLen );
		rsaKeyTemplate[ 11 ].pValue = rsaKey->q;
		rsaKeyTemplate[ 11 ].ulValueLen = bitsToBytes( rsaKey->qLen );
		rsaKeyTemplate[ 12 ].pValue = rsaKey->e1;
		rsaKeyTemplate[ 12 ].ulValueLen = bitsToBytes( rsaKey->e1Len );
		rsaKeyTemplate[ 13 ].pValue = rsaKey->e2;
		rsaKeyTemplate[ 13 ].ulValueLen = bitsToBytes( rsaKey->e2Len );
		rsaKeyTemplate[ 14 ].pValue = rsaKey->u;
		rsaKeyTemplate[ 14 ].ulValueLen = bitsToBytes( rsaKey->uLen );
		}
	else
		{
		/* If it's a public key, we need to change the type and indication of 
		   the operations it's allowed to perform */
		rsaKeyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubKeyClass;
		rsaKeyTemplate[ 3 ].type = CKA_VERIFY;
		rsaKeyTemplate[ 4 ].type = CKA_ENCRYPT;
		}

	/* Load the key into the token */
	status = C_CreateObject( pkcs11Info->hSession, rsaKeyTemplate, 
							 templateCount, &hRsaKey );
	zeroise( rsaKeyTemplate, sizeof( CK_ATTRIBUTE ) * templateCount );
	cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		{
		/* If we're trying to set a public key and this is one of those
		   tinkertoy tokens that only does private-key ops, return a more
		   appropriate error code */
		if( rsaKey->isPublicKey && \
			contextInfoPtr->capabilityInfo->encryptFunction == NULL &&
			contextInfoPtr->capabilityInfo->sigCheckFunction == NULL )
			cryptStatus = CRYPT_ERROR_NOTAVAIL;

		krnlReleaseObject( deviceInfo->objectHandle );
		return( cryptStatus );
		}

	/* Send the keying info to the context and set up the key ID info */
	cryptStatus = rsaSetPublicComponents( pkcs11Info, 
										  contextInfoPtr->objectHandle, hRsaKey );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = rsaSetKeyInfo( pkcs11Info, contextInfoPtr, 
									 hRsaKey, CRYPT_UNUSED );
	if( cryptStatusError( cryptStatus ) )
		C_DestroyObject( pkcs11Info->hSession, hRsaKey );

	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

static int rsaGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keysizeBits )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	static const CK_BBOOL bTrue = TRUE;
	static const BYTE exponent[] = { 0x01, 0x00, 0x01 };
	const CK_ULONG modulusBits = keysizeBits;
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SENSITIVE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, contextInfoPtr->label, contextInfoPtr->labelSize },
		{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		};
	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, contextInfoPtr->label, contextInfoPtr->labelSize },
		{ CKA_ENCRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_VERIFY, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PUBLIC_EXPONENT, ( CK_VOID_PTR ) exponent, sizeof( exponent ) },
		{ CKA_MODULUS_BITS, NULL, sizeof( CK_ULONG ) }
		};
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	PKCS11_INFO *pkcs11Info;
	CK_RV status;
	int cryptStatus;

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	pkcs11Info = deviceInfo->devicePKCS11;
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Patch in the key size and generate the keys */
	publicKeyTemplate[ 5 ].pValue = ( CK_VOID_PTR ) &modulusBits;
	status = C_GenerateKeyPair( pkcs11Info->hSession,
								( CK_MECHANISM_PTR ) &mechanism,
								publicKeyTemplate, 6, privateKeyTemplate, 6,
								&hPublicKey, &hPrivateKey );
	cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		{
		krnlReleaseObject( deviceInfo->objectHandle );
		return( cryptStatus );
		}

	/* Send the keying info to the context and set up the key ID info */
	cryptStatus = rsaSetPublicComponents( pkcs11Info, 
										  contextInfoPtr->objectHandle, 
										  hPublicKey );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = rsaSetKeyInfo( pkcs11Info, contextInfoPtr, hPrivateKey, 
									 hPublicKey );
	if( cryptStatusError( cryptStatus ) )
		{
		C_DestroyObject( pkcs11Info->hSession, hPublicKey );
		C_DestroyObject( pkcs11Info->hSession, hPrivateKey );
		}

	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

static int rsaSign( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE *bufPtr = buffer;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
	int cryptStatus, i;

	assert( length == keySize );

	/* Undo the PKCS #1 padding to make CKM_RSA_PKCS look like 
	   CKM_RSA_X_509 */
	assert( bufPtr[ 0 ] == 0 && bufPtr[ 1 ] == 1 && bufPtr[ 2 ] == 0xFF );
	for( i = 2; i < keySize; i++ )
		if( bufPtr[ i ] == 0 )
			break;
	i++;	/* Skip final 0 byte */

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	cryptStatus = genericSign( deviceInfo->devicePKCS11, contextInfoPtr, 
							   &mechanism, bufPtr + i, keySize - i, 
							   buffer, keySize );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

static int rsaVerify( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE data[ CRYPT_MAX_PKCSIZE ];
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
	int cryptStatus;

	/* This function is present but isn't used as part of any normal 
	   operation because cryptlib does the same thing much faster in 
	   software and because some tokens don't support public-key 
	   operations */

	assert( length == keySize );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	cryptStatus = genericVerify( deviceInfo->devicePKCS11, contextInfoPtr, 
								 &mechanism, data, keySize, buffer, keySize );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

static int rsaEncrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE *bufPtr = buffer;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
	int cryptStatus, i;

	/* This function is present but isn't used as part of any normal 
	   operation because cryptlib does the same thing much faster in 
	   software and because some tokens don't support public-key 
	   operations.  The only way that it can be invoked is by calling
	   cryptEncrypt() directly on a device context */

	assert( length == keySize );

	/* Undo the PKCS #1 padding to make CKM_RSA_PKCS look like 
	   CKM_RSA_X_509 */
	assert( bufPtr[ 0 ] == 0 && bufPtr[ 1 ] == 2 );
	for( i = 2; i < keySize; i++ )
		if( bufPtr[ i ] == 0 )
			break;
	i++;	/* Skip final 0 byte */
	memmove( bufPtr, bufPtr + i, keySize - i );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	cryptStatus = genericEncrypt( deviceInfo->devicePKCS11, contextInfoPtr, 
								  &mechanism, bufPtr, keySize - i, keySize );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

static int rsaDecrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE *bufPtr = buffer;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
	int cryptStatus, resultLen, i;

	assert( length == keySize );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	cryptStatus = genericDecrypt( deviceInfo->devicePKCS11, contextInfoPtr, 
								  &mechanism, buffer, keySize, &resultLen );
	krnlReleaseObject( deviceInfo->objectHandle );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* Redo the PKCS #1 padding to CKM_RSA_PKCS look like CKM_RSA_X_509 */
	memmove( bufPtr + keySize - resultLen, bufPtr, resultLen );
	bufPtr[ 0 ] = 0;
	bufPtr[ 1 ] = 2;
	for( i = 2; i < keySize - resultLen - 1; i++ )
		bufPtr[ i ] = 0xA5;
	bufPtr[ i ] = 0;
	assert( i + 1 + resultLen == keySize );

	return( CRYPT_OK );
	}

/* DSA algorithm-specific mapping functions */

static int dsaSetKeyInfo( PKCS11_INFO *pkcs11Info, 
						  CONTEXT_INFO *contextInfoPtr, 
						  const CK_OBJECT_HANDLE hPrivateKey,
						  const CK_OBJECT_HANDLE hPublicKey,
						  const void *p, const int pLen,
						  const void *q, const int qLen,
						  const void *g, const int gLen,
						  const void *y, const int yLen )
	{
	RESOURCE_DATA msgData;
	BYTE keyDataBuffer[ CRYPT_MAX_PKCSIZE * 3 ], idBuffer[ KEYID_SIZE ];
	int keyDataSize, cryptStatus;

	/* Send the public key data to the context.  We send the keying info as
	   CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL rather than CRYPT_IATTRIBUTE_KEY_SPKI
	   since the latter transitions the context into the high state.  We 
	   don't want to do this because we're already in the middle of processing
	   a message that does this on completion, all we're doing here is 
	   sending in encoded public key data for use by objects such as 
	   certificates */
	cryptStatus = keyDataSize = writeFlatPublicKey( NULL, 0, CRYPT_ALGO_DSA, 
													p, pLen, q, qLen, g, gLen, 
													y, yLen );
	if( !cryptStatusError( cryptStatus ) )
		cryptStatus = writeFlatPublicKey( keyDataBuffer, CRYPT_MAX_PKCSIZE * 3,
										  CRYPT_ALGO_DSA, p, pLen, q, qLen, 
										  g, gLen, y, yLen );
	if( !cryptStatusError( cryptStatus ) )
		cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
									   IMESSAGE_SETATTRIBUTE, 
									   ( void * ) &pLen, CRYPT_IATTRIBUTE_KEYSIZE );
	if( cryptStatusOK( cryptStatus ) )
		{
		setMessageData( &msgData, keyDataBuffer, keyDataSize );
		cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
									   IMESSAGE_SETATTRIBUTE_S, &msgData, 
									   CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL );
		}
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* Remember what we've set up */
	krnlSendMessage( contextInfoPtr->objectHandle, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &hPrivateKey, CRYPT_IATTRIBUTE_DEVICEOBJECT );

	/* Get the key ID from the context and use it as the object ID.  Since 
	   some objects won't allow after-the-even ID updates, we don't treat a
	   failure to update as an error */
	setMessageData( &msgData, idBuffer, KEYID_SIZE );
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETATTRIBUTE_S, &msgData, 
								   CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusOK( cryptStatus ) )
		{
		CK_ATTRIBUTE idTemplate = { CKA_ID, msgData.data, msgData.length };

		if( hPublicKey != CRYPT_UNUSED )
			C_SetAttributeValue( pkcs11Info->hSession, hPublicKey, 
								 &idTemplate, 1 );
		C_SetAttributeValue( pkcs11Info->hSession, hPrivateKey, 
							 &idTemplate, 1 );
		}
	
	return( cryptStatus );
	}

static int dsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					   const int keyLength )
	{
	static const CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	static const CK_KEY_TYPE type = CKK_DSA;
	static const CK_BBOOL bTrue = TRUE;
	CK_ATTRIBUTE dsaKeyTemplate[] = {
		/* Shared fields */
		{ CKA_CLASS, ( CK_VOID_PTR ) &privKeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &type, sizeof( CK_KEY_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, contextInfoPtr->label, contextInfoPtr->labelSize },
		{ CKA_PRIME, NULL, 0 },
		{ CKA_SUBPRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		{ CKA_VALUE, NULL, 0 },
		/* Private-key only fields */
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		};
	CRYPT_PKCINFO_DLP *dsaKey = ( CRYPT_PKCINFO_DLP * ) key;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	PKCS11_INFO *pkcs11Info;
	CK_OBJECT_HANDLE hDsaKey;
	CK_RV status;
	BYTE yValue[ CRYPT_MAX_PKCSIZE ];
	const int templateCount = dsaKey->isPublicKey ? 9 : 10;
	int yValueLength, cryptStatus;

	/* Creating a private-key object is somewhat problematic since the 
	   PKCS #11 interpretation of DSA reuses CKA_VALUE for x in the private
	   key and y in the public key, so it's not possible to determine y from
	   a private key because the x value is sensitive and can't be extracted.
	   Because of this we have to create a native private-key context (which 
	   will generate the y value from x), read out the y value, and destroy
	   it again (see the comments in the DSA generate key section for more on
	   this problem).  Since this doesn't require the device, we do it before 
	   we grab the device */
	if( !dsaKey->isPublicKey )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;
		RESOURCE_DATA msgData;
		STREAM stream;
		BYTE pubkeyBuffer[ CRYPT_MAX_PKCSIZE * 2 ], label[ 8 ];

		/* Create a native private-key DSA context, which generates the y 
		   value internally */
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DSA );
		cryptStatus = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									   IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
									   OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( cryptStatus ) )
			return( cryptStatus );
		setMessageData( &msgData, label, 8 );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S, 
						 &msgData, CRYPT_CTXINFO_LABEL );
		setMessageData( &msgData, dsaKey, sizeof( CRYPT_PKCINFO_DLP ) );
		cryptStatus = krnlSendMessage( createInfo.cryptHandle, 
									   IMESSAGE_SETATTRIBUTE_S, &msgData, 
									   CRYPT_CTXINFO_KEY_COMPONENTS );
		if( cryptStatusError( cryptStatus ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( cryptStatus );
			}

		/* Get the public key data and extract the y value from it.  Note 
		   that the data used is represented in DER-canonical form, there may 
		   be PKCS #11 implementations that can't handle this (for example 
		   they may require y to be zero-padded to make it exactly 64 bytes 
		   rather than (say) 63 bytes if the high byte is zero) */
		setMessageData( &msgData, pubkeyBuffer, CRYPT_MAX_PKCSIZE * 2 );
		cryptStatus = krnlSendMessage( createInfo.cryptHandle, 
									   IMESSAGE_GETATTRIBUTE_S, &msgData, 
									   CRYPT_IATTRIBUTE_KEY_SPKI );
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( cryptStatus ) )
			return( cryptStatus );
		sMemConnect( &stream, msgData.data, msgData.length );
		readSequence( &stream, NULL );		/* SEQUENCE { */
		readUniversal( &stream );				/* AlgoID */
		readBitStringHole( &stream, NULL, DEFAULT_TAG );	/* BIT STRING */
		readGenericHole( &stream, &yValueLength, BER_INTEGER  );/* INTEGER */
		memcpy( yValue, sMemBufPtr( &stream ), yValueLength );
		sMemDisconnect( &stream );
		}

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	pkcs11Info = deviceInfo->devicePKCS11;
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Set up the key values */
	dsaKeyTemplate[ 5 ].pValue = dsaKey->p;
	dsaKeyTemplate[ 5 ].ulValueLen = bitsToBytes( dsaKey->pLen );
	dsaKeyTemplate[ 6 ].pValue = dsaKey->q;
	dsaKeyTemplate[ 6 ].ulValueLen = bitsToBytes( dsaKey->qLen );
	dsaKeyTemplate[ 7 ].pValue = dsaKey->g;
	dsaKeyTemplate[ 7 ].ulValueLen = bitsToBytes( dsaKey->gLen );
	if( !dsaKey->isPublicKey )
		{
		dsaKeyTemplate[ 8 ].pValue = dsaKey->x;
		dsaKeyTemplate[ 8 ].ulValueLen = bitsToBytes( dsaKey->xLen );
		}
	else
		{
		dsaKeyTemplate[ 8 ].pValue = dsaKey->y;
		dsaKeyTemplate[ 8 ].ulValueLen = bitsToBytes( dsaKey->yLen );

		/* If it's a public key, we need to change the type and the 
		   indication of the operations that it's allowed to perform */
		dsaKeyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubKeyClass;
		dsaKeyTemplate[ 3 ].type = CKA_VERIFY;
		}

	/* Load the key into the token */
	status = C_CreateObject( pkcs11Info->hSession, dsaKeyTemplate, 
							 templateCount, &hDsaKey );
	zeroise( dsaKeyTemplate, sizeof( CK_ATTRIBUTE ) * templateCount );
	cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		{
		/* If we're trying to set a public key and this is one of those
		   tinkertoy tokens that only does private-key ops, return a more
		   appropriate error code */
		if( dsaKey->isPublicKey && \
			contextInfoPtr->capabilityInfo->sigCheckFunction == NULL )
			cryptStatus = CRYPT_ERROR_NOTAVAIL;

		krnlReleaseObject( deviceInfo->objectHandle );
		return( cryptStatus );
		}

	/* Send the keying info to the context and set up the key ID info */
	cryptStatus = dsaSetKeyInfo( pkcs11Info, contextInfoPtr, 
								 hDsaKey, CRYPT_UNUSED,
								 dsaKey->p, bitsToBytes( dsaKey->pLen ), 
								 dsaKey->q, bitsToBytes( dsaKey->qLen ),
								 dsaKey->g, bitsToBytes( dsaKey->gLen ),
								 ( dsaKey->isPublicKey ) ? dsaKey->y : yValue,
								 ( dsaKey->isPublicKey ) ? \
									bitsToBytes( dsaKey->yLen ) : yValueLength );
	if( cryptStatusError( cryptStatus ) )
		C_DestroyObject( pkcs11Info->hSession, hDsaKey );

	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

static int dsaGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keysizeBits )
	{
	static const CK_MECHANISM mechanism = { CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
	static const CK_BBOOL bTrue = TRUE;
	const CK_ULONG modulusBits = keysizeBits;
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SENSITIVE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, contextInfoPtr->label, contextInfoPtr->labelSize },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		};
	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, contextInfoPtr->label, contextInfoPtr->labelSize },
		{ CKA_VERIFY, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIME, NULL, 0 },
		{ CKA_SUBPRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		};
	CK_ATTRIBUTE yValueTemplate = { CKA_VALUE, NULL, CRYPT_MAX_PKCSIZE * 2 };
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	PKCS11_INFO *pkcs11Info;
	BYTE pubkeyBuffer[ CRYPT_MAX_PKCSIZE * 2 ], label[ 8 ];
	CK_RV status;
	STREAM stream;
	long length;
	int keyLength = bitsToBytes( keysizeBits ), cryptStatus;

	/* CKM_DSA_KEY_PAIR_GEN is really a Clayton's key generation mechanism 
	   since it doesn't actually generate the p, q, or g values (presumably 
	   it dates back to the original FIPS 186 shared domain parameters idea).
	   Because of this we'd have to generate half the key ourselves in a 
	   native context, then copy portions from the native context over in 
	   flat form and complete the keygen via the device.  The easiest way to
	   do this is to create a native DSA context, generate a key, grab the
	   public portions, and destroy the context again (i.e. generate a full
	   key on a superscalar 2GHz RISC CPU, then throw half of it away, and 
	   regenerate it on a 5MHz 8-bit tinkertoy).  Since the keygen can take 
	   awhile and doesn't require the device, we do it before we grab the 
	   device */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DSA );
	cryptStatus = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								   IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								   OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	setMessageData( &msgData, label, 8 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
					 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_LABEL );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( int * ) &keyLength, CRYPT_CTXINFO_KEYSIZE );
	cryptStatus = krnlSendMessage( createInfo.cryptHandle, 
								   IMESSAGE_CTX_GENKEY, NULL, FALSE );
	if( cryptStatusOK( cryptStatus ) )
		{
		setMessageData( &msgData, pubkeyBuffer, CRYPT_MAX_PKCSIZE * 2 );
		cryptStatus = krnlSendMessage( createInfo.cryptHandle, 
									   IMESSAGE_GETATTRIBUTE_S, &msgData, 
									   CRYPT_IATTRIBUTE_KEY_SPKI );
		}
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* Set up the public key info by extracting the flat values from the
	   SubjectPublicKeyInfo.  Note that the data used is represented in
	   DER-canonical form, there may be PKCS #11 implementations that
	   can't handle this (for example they may require q to be zero-padded
	   to make it exactly 20 bytes rather than (say) 19 bytes if the high
	   byte is zero) */
	sMemConnect( &stream, pubkeyBuffer, msgData.length );
	readSequence( &stream, NULL );				/* SEQUENCE */
	readSequence( &stream, NULL );					/* SEQUENCE */
	readUniversal( &stream );							/* OID */
	readSequence( &stream, NULL );						/* SEQUENCE */
	readGenericHole( &stream, &length, BER_INTEGER  );		/* p */
	publicKeyTemplate[ 3 ].pValue = sMemBufPtr( &stream );
	publicKeyTemplate[ 3 ].ulValueLen = length;
	sSkip( &stream, length );
	readGenericHole( &stream, &length, BER_INTEGER  );		/* q */
	publicKeyTemplate[ 4 ].pValue = sMemBufPtr( &stream );
	publicKeyTemplate[ 4 ].ulValueLen = length;
	sSkip( &stream, length );
	readGenericHole( &stream, &length, BER_INTEGER  );		/* g */
	publicKeyTemplate[ 5 ].pValue = sMemBufPtr( &stream );
	publicKeyTemplate[ 5 ].ulValueLen = length;
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	pkcs11Info = deviceInfo->devicePKCS11;
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Generate the keys */
	status = C_GenerateKeyPair( pkcs11Info->hSession,
								( CK_MECHANISM_PTR ) &mechanism,
								( CK_ATTRIBUTE_PTR ) publicKeyTemplate, 5,
								( CK_ATTRIBUTE_PTR ) privateKeyTemplate, 4,
								&hPublicKey, &hPrivateKey );
	cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		{
		krnlReleaseObject( deviceInfo->objectHandle );
		return( cryptStatus );
		}

	/* Read back the generated y value, send the public key info to the 
	   context, and set up the key ID info.  The odd two-phase y value read 
	   is necessary for buggy implementations that fail if the given size 
	   isn't exactly the same as the data size */
	status = C_GetAttributeValue( pkcs11Info->hSession, hPublicKey,
								  &yValueTemplate, 1 );
	if( status == CKR_OK )
		{
		yValueTemplate.pValue = pubkeyBuffer;
		status = C_GetAttributeValue( pkcs11Info->hSession, hPublicKey, 
									  &yValueTemplate, 1 );
		}
	cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = dsaSetKeyInfo( pkcs11Info, contextInfoPtr, 
			hPrivateKey, hPublicKey,
			publicKeyTemplate[ 3 ].pValue, publicKeyTemplate[ 3 ].ulValueLen, 
			publicKeyTemplate[ 4 ].pValue, publicKeyTemplate[ 4 ].ulValueLen, 
			publicKeyTemplate[ 5 ].pValue, publicKeyTemplate[ 5 ].ulValueLen,
			yValueTemplate.pValue, yValueTemplate.ulValueLen );
	if( cryptStatusError( cryptStatus ) )
		{
		C_DestroyObject( pkcs11Info->hSession, hPublicKey );
		C_DestroyObject( pkcs11Info->hSession, hPrivateKey );
		}

	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

static int dsaSign( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_DSA, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) buffer;
	DEVICE_INFO *deviceInfo;
	BIGNUM *r, *s;
	BYTE signature[ 40 ];
	int cryptStatus;

	assert( length == sizeof( DLP_PARAMS ) );
	assert( dlpParams->inParam1 != NULL && \
			dlpParams->inLen1 == 20 );
	assert( dlpParams->inParam2 == NULL && dlpParams->inLen2 == 0 );
	assert( dlpParams->outParam != NULL && \
			dlpParams->outLen >= ( 2 + 20 ) * 2 );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	cryptStatus = genericSign( deviceInfo->devicePKCS11, contextInfoPtr, 
							   &mechanism, dlpParams->inParam1, 
							   dlpParams->inLen1, signature, 40 );
	krnlReleaseObject( deviceInfo->objectHandle );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* Encode the result as a DL data block.  We have to do this via bignums, 
	   but this isn't a big deal since DSA signing via tokens is almost never 
	   used */
	r = BN_new();
	s = BN_new();
	if( r != NULL && s != NULL )
		{
		BN_bin2bn( signature, 20, r );
		BN_bin2bn( signature + 20, 20, s );
		cryptStatus = encodeDLValues( dlpParams->outParam, dlpParams->outLen, 
									  r, s, dlpParams->formatType );
		if( !cryptStatusError( cryptStatus ) )
			{
			dlpParams->outLen = cryptStatus;
			cryptStatus = CRYPT_OK;	/* encodeDLValues() returns a byte count */
			}
		BN_clear_free( s );
		BN_clear_free( r );
		}
	return( cryptStatus );
	}

static int dsaVerify( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_DSA, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) buffer;
	DEVICE_INFO *deviceInfo;
	BIGNUM *r, *s;
	BYTE signature[ 40 ];
	int cryptStatus;

	/* This function is present but isn't used as part of any normal 
	   operation because cryptlib does the same thing much faster in 
	   software and because some tokens don't support public-key 
	   operations */

	assert( length == sizeof( DLP_PARAMS ) );
	assert( dlpParams->inParam1 != NULL && dlpParams->inLen1 == 20 );
	assert( dlpParams->inParam2 != NULL && \
			( ( dlpParams->formatType == CRYPT_FORMAT_CRYPTLIB && \
				dlpParams->inLen2 >= 46 ) || \
			  ( dlpParams->formatType == CRYPT_FORMAT_PGP && \
				dlpParams->inLen2 == 44 ) || \
				( dlpParams->formatType == CRYPT_IFORMAT_SSH && \
				dlpParams->inLen2 == 40 ) ) );
	assert( dlpParams->outParam == NULL && dlpParams->outLen == 0 );

	/* Decode the values from a DL data block and make sure r and s are
	   valid */
	cryptStatus = decodeDLValues( dlpParams->inParam2, dlpParams->inLen2, 
								  &r, &s, dlpParams->formatType );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* This code can never be called, since DSA public-key contexts are 
	   always native contexts */
	assert( NOTREACHED );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	cryptStatus = genericVerify( deviceInfo->devicePKCS11, contextInfoPtr, 
								 &mechanism, buffer, 20, signature, 40 );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

/* Conventional cipher-specific mapping functions */

static void adjustKeyParity( BYTE *key, const int length )
	{
	int i;

	/* Adjust a key to have odd parity, needed for DES keys */
	for( i = 0; i < length; i++ )
		{
		BYTE ch = key[ i ];
		
		ch = ( ch & 0x55 ) + ( ( ch >> 1 ) & 0x55 );
		ch = ( ch & 0x33 ) + ( ( ch >> 2 ) & 0x33 );
		if( !( ( ch + ( ch >> 4 ) ) & 0x01 ) )
			key[ i ] ^= 1;
		}
	}

static int cipherInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
						  const int keyLength )
	{
	static const CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	const CK_KEY_TYPE type = contextInfoPtr->capabilityInfo->paramKeyType;
	static const CK_BBOOL bFalse = FALSE, bTrue = TRUE;
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &class, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &type, sizeof( CK_KEY_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bFalse, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SENSITIVE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_ENCRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_VALUE, NULL_PTR, 0 }
		};
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	PKCS11_INFO *pkcs11Info;
	CK_OBJECT_HANDLE hObject;
	CK_RV status;
	int keySize = ( type == CKK_DES || type == CKK_DES3 || \
					type == CKK_IDEA || type == CKK_SKIPJACK ) ? \
					contextInfoPtr->capabilityInfo->keySize : keyLength;
	int cryptStatus;

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	pkcs11Info = deviceInfo->devicePKCS11;
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Copy the key to internal storage */
	if( contextInfoPtr->ctxConv->userKey != key )
		memcpy( contextInfoPtr->ctxConv->userKey, key, keyLength );
	contextInfoPtr->ctxConv->userKeyLength = keyLength;

	/* Special-case handling for 2-key vs.3-key 3DES */
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_3DES )
		{
		/* If the supplied key contains only two DES keys, adjust the key to
		   make it the equivalent of 3-key 3DES.  In addition since the
		   nominal keysize is for 2-key 3DES, we have to make the actual size
		   the maximum size, corresponding to 3-key 3DES */
		if( keyLength <= bitsToBytes( 64 * 2 ) )
			memcpy( contextInfoPtr->ctxConv->userKey + bitsToBytes( 64 * 2 ),
					contextInfoPtr->ctxConv->userKey, bitsToBytes( 64 ) );
		keySize = contextInfoPtr->capabilityInfo->maxKeySize;
		}

	/* If we're using DES we have to adjust the key parity because the spec
	   says so, almost all implementations do this anyway but there's always
	   the odd one out that we have to cater for */
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DES || \
		contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_3DES )
		adjustKeyParity( contextInfoPtr->ctxConv->userKey, keySize );

	/* Set up the key values.  Since the key passed in by the user may be
	   smaller than the keysize required by algorithms that use fixed-size
	   keys, we use the (optionally) zero-padded key of the correct length 
	   held in the context rather than the variable-length user-supplied 
	   one */
	keyTemplate[ 7 ].pValue = contextInfoPtr->ctxConv->userKey;
	keyTemplate[ 7 ].ulValueLen = keySize;

	/* Load the key into the token */
	status = C_CreateObject( pkcs11Info->hSession,
							 ( CK_ATTRIBUTE_PTR ) keyTemplate, 8, &hObject );
	cryptStatus = mapError( pkcs11Info, status, CRYPT_ERROR_FAILED );
	if( cryptStatusOK( cryptStatus ) )
		contextInfoPtr->deviceObject = hObject;
	zeroise( keyTemplate, sizeof( CK_ATTRIBUTE ) * 8 );

	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

/* Set up algorithm-specific encryption parameters */

static int initCryptParams( CONTEXT_INFO *contextInfoPtr, void *paramData )
	{
	const int ivSize = contextInfoPtr->capabilityInfo->blockSize;

	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC2 )
		{
		if( contextInfoPtr->ctxConv->mode == CRYPT_MODE_ECB )
			{
			CK_RC2_PARAMS_PTR rc2params = ( CK_RC2_PARAMS_PTR ) paramData;

			*rc2params = 128;
			return( sizeof( CK_RC2_PARAMS ) );
			}
		else
			{
			CK_RC2_CBC_PARAMS_PTR rc2params = ( CK_RC2_CBC_PARAMS_PTR ) paramData;

			rc2params->ulEffectiveBits = 128;
			memcpy( rc2params->iv, contextInfoPtr->ctxConv->currentIV, ivSize );
			return( sizeof( CK_RC2_CBC_PARAMS ) );
			}
		}
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC5 )
		{
		if( contextInfoPtr->ctxConv->mode == CRYPT_MODE_ECB )
			{
			CK_RC5_PARAMS_PTR rc5params = ( CK_RC5_PARAMS_PTR ) paramData;

			rc5params->ulWordsize = 4;	/* Word size in bytes = blocksize/2 */
			rc5params->ulRounds = 12;
			return( sizeof( CK_RC5_PARAMS ) );
			}
		else
			{
			CK_RC5_CBC_PARAMS_PTR rc5params = ( CK_RC5_CBC_PARAMS_PTR ) paramData;

			rc5params->ulWordsize = 4;	/* Word size in bytes = blocksize/2 */
			rc5params->ulRounds = 12;
			rc5params->pIv = contextInfoPtr->ctxConv->currentIV;
			rc5params->ulIvLen = ivSize;
			return( sizeof( CK_RC5_CBC_PARAMS ) );
			}
		}
	return( 0 );
	}

static int cipherEncrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length, const CK_MECHANISM_TYPE mechanismType )
	{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	PKCS11_INFO *pkcs11Info;
	BYTE paramDataBuffer[ 64 ];
	const int ivSize = contextInfoPtr->capabilityInfo->blockSize;
	int paramSize, cryptStatus;

	/* Set up algorithm and mode-specific parameters */
	paramSize = initCryptParams( contextInfoPtr, &paramDataBuffer );
	if( paramSize )
		{
		mechanism.pParameter = paramDataBuffer;
		mechanism.ulParameterLen = paramSize;
		}
	else
		/* Even if there are no algorithm-specific parameters, there may 
		   still be a mode-specific IV parameter */
		if( needsIV( contextInfoPtr->ctxConv->mode ) && \
			!isStreamCipher( contextInfoPtr->capabilityInfo->cryptAlgo ) )
			{
			mechanism.pParameter = contextInfoPtr->ctxConv->currentIV;
			mechanism.ulParameterLen = ivSize;
			}

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	pkcs11Info = deviceInfo->devicePKCS11;
	cryptStatus = genericEncrypt( pkcs11Info, contextInfoPtr, &mechanism, buffer,
								  length, length );
	if( cryptStatusOK( cryptStatus ) )
		{
		if( needsIV( contextInfoPtr->ctxConv->mode ) && \
			!isStreamCipher( contextInfoPtr->capabilityInfo->cryptAlgo ) )
			/* Since PKCS #11 assumes that either all data is encrypted at 
			   once or that a given mechanism is devoted entirely to a single 
			   operation, we have to preserve the state (the IV) across 
			   calls */
			memcpy( contextInfoPtr->ctxConv->currentIV, \
					( BYTE * ) buffer + length - ivSize, ivSize );
		}
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

static int cipherDecrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length, const CK_MECHANISM_TYPE mechanismType )
	{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	PKCS11_INFO *pkcs11Info;
	BYTE paramDataBuffer[ 64 ], ivBuffer[ CRYPT_MAX_IVSIZE ];
	const int ivSize = contextInfoPtr->capabilityInfo->blockSize;
	int paramSize, cryptStatus;

	/* Set up algorithm and mode-specific parameters */
	paramSize = initCryptParams( contextInfoPtr, &paramDataBuffer );
	if( paramSize )
		{
		mechanism.pParameter = paramDataBuffer;
		mechanism.ulParameterLen = paramSize;
		}
	else
		/* Even if there are no algorithm-specific parameters, there may 
		   still be a mode-specific IV parameter.  In addition we have to
		   save the end of the ciphertext as the IV for the next block if
		   this is required */
		if( needsIV( contextInfoPtr->ctxConv->mode ) && \
			!isStreamCipher( contextInfoPtr->capabilityInfo->cryptAlgo ) )
			{
			mechanism.pParameter = contextInfoPtr->ctxConv->currentIV;
			mechanism.ulParameterLen = ivSize;
			}
	if( needsIV( contextInfoPtr->ctxConv->mode ) && \
		!isStreamCipher( contextInfoPtr->capabilityInfo->cryptAlgo ) )
		memcpy( ivBuffer, ( BYTE * ) buffer + length - ivSize, ivSize );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( contextInfoPtr->objectHandle, 
								   IMESSAGE_GETDEPENDENT, &iCryptDevice, 
								   OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
									 ( void ** ) &deviceInfo, 
									 CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	pkcs11Info = deviceInfo->devicePKCS11;
	cryptStatus = genericDecrypt( pkcs11Info, contextInfoPtr, &mechanism, buffer,
								  length, NULL );
	if( cryptStatusOK( cryptStatus ) )
		{
		if( needsIV( contextInfoPtr->ctxConv->mode ) && \
			!isStreamCipher( contextInfoPtr->capabilityInfo->cryptAlgo ) )
			/* Since PKCS #11 assumes that either all data is encrypted at 
			   once or that a given mechanism is devoted entirely to a single 
			   operation, we have to preserve the state (the IV) across 
			   calls */
			memcpy( contextInfoPtr->ctxConv->currentIV, ivBuffer, ivSize );
		}
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
	}

/* Map a cryptlib algorithm and mode to a PKCS #11 mechanism type, with
   shortcuts for the most frequently-used algorithm(s) */

STATIC_FN CK_MECHANISM_TYPE getMechanism( const CRYPT_ALGO_TYPE cryptAlgo,
										  const CRYPT_MODE_TYPE cryptMode );

static int cipherEncryptECB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							 int length )
	{
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_3DES )
		return( cipherEncrypt( contextInfoPtr, buffer, length, CKM_DES3_ECB ) );
	return( cipherEncrypt( contextInfoPtr, buffer, length, 
						   getMechanism( contextInfoPtr->capabilityInfo->cryptAlgo, 
										 CRYPT_MODE_ECB ) ) );
	}
static int cipherEncryptCBC( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							 int length )
	{
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_3DES )
		return( cipherEncrypt( contextInfoPtr, buffer, length, CKM_DES3_CBC ) );
	return( cipherEncrypt( contextInfoPtr, buffer, length, 
						   getMechanism( contextInfoPtr->capabilityInfo->cryptAlgo, 
										 CRYPT_MODE_CBC ) ) );
	}
static int cipherEncryptCFB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							 int length )
	{
	return( cipherEncrypt( contextInfoPtr, buffer, length, 
						   getMechanism( contextInfoPtr->capabilityInfo->cryptAlgo, 
										 CRYPT_MODE_CFB ) ) );
	}
static int cipherEncryptOFB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							 int length )
	{
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC4 )
		return( cipherEncrypt( contextInfoPtr, buffer, length, CKM_RC4 ) );
	return( cipherEncrypt( contextInfoPtr, buffer, length, 
						   getMechanism( contextInfoPtr->capabilityInfo->cryptAlgo, 
										 CRYPT_MODE_OFB ) ) );
	}
static int cipherDecryptECB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							 int length )
	{
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_3DES )
		return( cipherDecrypt( contextInfoPtr, buffer, length, CKM_DES3_ECB ) );
	return( cipherDecrypt( contextInfoPtr, buffer, length, 
						   getMechanism( contextInfoPtr->capabilityInfo->cryptAlgo, 
										 CRYPT_MODE_ECB ) ) );
	}
static int cipherDecryptCBC( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							 int length )
	{
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_3DES )
		return( cipherDecrypt( contextInfoPtr, buffer, length, CKM_DES3_CBC ) );
	return( cipherDecrypt( contextInfoPtr, buffer, length, 
						   getMechanism( contextInfoPtr->capabilityInfo->cryptAlgo, 
										 CRYPT_MODE_CBC ) ) );
	}
static int cipherDecryptCFB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							 int length )
	{
	return( cipherDecrypt( contextInfoPtr, buffer, length, 
						   getMechanism( contextInfoPtr->capabilityInfo->cryptAlgo, 
										 CRYPT_MODE_CFB ) ) );
	}
static int cipherDecryptOFB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							 int length )
	{
	if( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC4 )
		return( cipherDecrypt( contextInfoPtr, buffer, length, CKM_RC4 ) );
	return( cipherDecrypt( contextInfoPtr, buffer, length, 
						   getMechanism( contextInfoPtr->capabilityInfo->cryptAlgo, 
										 CRYPT_MODE_OFB ) ) );
	}

/****************************************************************************
*																			*
*						 	Device Capability Routines						*
*																			*
****************************************************************************/

/* The reported key size for PKCS #11 implementations is rather inconsistent,
   most are reported in bits, a number don't return a useful value, and a few
   are reported in bytes.  The following macros sort out which algorithms
   have valid key size info and which report the length in bytes */

#define keysizeValid( algo ) \
	( ( algo ) == CRYPT_ALGO_RSA || ( algo ) == CRYPT_ALGO_DSA || \
	  ( algo ) == CRYPT_ALGO_RC2 || ( algo ) == CRYPT_ALGO_RC4 || \
	  ( algo ) == CRYPT_ALGO_RC5 || ( algo ) == CRYPT_ALGO_CAST )
#define keysizeBytes( algo ) \
	( ( algo ) == CRYPT_ALGO_RC5 || ( algo ) == CRYPT_ALGO_CAST )

/* Since cryptlib's CAPABILITY_INFO is fixed, all of the fields are declared
   const so that they'll (hopefully) be allocated in the code segment.  This 
   doesn't quite work for PKCS #11 devices since things like the available key
   lengths can vary depending on the device that's plugged in, so we declare 
   an equivalent structure here that makes the variable fields non-const.  
   Once the fields are set up, the result is copied into a dynamically-
   allocated CAPABILITY_INFO block at which point the fields are treated as 
   const by the code */

typedef struct {
	const CRYPT_ALGO_TYPE cryptAlgo;
	const int blockSize;
	const char *algoName;
	int minKeySize;						/* Non-const */
	int keySize;						/* Non-const */
	int maxKeySize;						/* Non-const */
	int ( *selfTestFunction )( void );
	int ( *getInfoFunction )( const CAPABILITY_INFO_TYPE type, 
							  void *varParam, const int constParam );
	int ( *endFunction )( struct CI *contextInfoPtr );
	int ( *initKeyParamsFunction )( struct CI *contextInfoPtr, const void *iv, 
									const int ivLength, const CRYPT_MODE_TYPE mode );
	int ( *initKeyFunction )( struct CI *contextInfoPtr, const void *key, 
							  const int keyLength );
	int ( *generateKeyFunction )( struct CI *contextInfoPtr, const int keySizeBits );
	int ( *encryptFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int ( *decryptFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int ( *encryptCBCFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int ( *decryptCBCFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int ( *encryptCFBFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int ( *decryptCFBFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int ( *encryptOFBFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int ( *decryptOFBFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int ( *signFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int ( *sigCheckFunction )( struct CI *contextInfoPtr, void *buffer, int length );
	int param1, param2, param3, param4;	/* Non-const */
	struct CA *next;
	} VARIABLE_CAPABILITY_INFO;

/* Templates for the various capabilities.  These contain only basic 
   information, the remaining fields are filled in when the capability is 
   set up */

#define bits(x)	bitsToBytes(x)

static CAPABILITY_INFO FAR_BSS capabilityTemplates[] = {
	/* Encryption capabilities */
	{ CRYPT_ALGO_DES, bits( 64 ), "DES",
		bits( 40 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_3DES, bits( 64 ), "3DES",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ) },
	{ CRYPT_ALGO_IDEA, bits( 64 ), "IDEA",
		bits( 40 ), bits( 128 ), bits( 128 ) },
	{ CRYPT_ALGO_CAST, bits( 64 ), "CAST-128",
		bits( 40 ), bits( 128 ), bits( 128 ) },
	{ CRYPT_ALGO_RC2, bits( 64 ), "RC2",
		bits( 40 ), bits( 128 ), bits( 1024 ) },
	{ CRYPT_ALGO_RC4, bits( 8 ), "RC4",
		bits( 40 ), bits( 128 ), 256 },
	{ CRYPT_ALGO_RC5, bits( 64 ), "RC5",
		bits( 40 ), bits( 128 ), bits( 832 ) },
	{ CRYPT_ALGO_AES, bits( 128 ), "AES",
		bits( 128 ), bits( 128 ), bits( 256 ) },
	{ CRYPT_ALGO_SKIPJACK, bits( 64 ), "Skipjack",
		bits( 80 ), bits( 80 ), bits( 80 ) },

	/* Hash capabilities */
	{ CRYPT_ALGO_MD2, bits( 128 ), "MD2",
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_MD5, bits( 128 ), "MD5",
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_SHA, bits( 160 ), "SHA",
		bits( 0 ), bits( 0 ), bits( 0 ) },

	/* Public-key capabilities */
	{ CRYPT_ALGO_RSA, bits( 0 ), "RSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE },
	{ CRYPT_ALGO_DSA, bits( 0 ), "DSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE },

	/* Hier ist der Mast zu ende */
	{ CRYPT_ERROR }
	};

/* Mapping of PKCS #11 device capabilities to cryptlib capabilities */

typedef struct {
	/* Mapping information.  Most PKC mechanisms have supplementary 
	   mechanisms used solely for key generation which doesn't make much 
	   sense, however it does mean that when checking the main mechanism for
	   keygen capabilities via the CKF_GENERATE_KEY_PAIR flag we have to make
	   a second check for the alternate mechanism since there's no consensus
	   over whether the presence of a keygen mechanism with a different ID
	   means the keygen flag should be set for the main mechanism */
	const CK_MECHANISM_TYPE mechanism;	/* PKCS #11 mechanism type */
	const CK_MECHANISM_TYPE keygenMechanism; /* Supplementary keygen mechanism */
	const CRYPT_ALGO_TYPE cryptAlgo;	/* cryptlib algo and mode */
	const CRYPT_MODE_TYPE cryptMode;

	/* Equivalent PKCS #11 parameters */
	const CK_KEY_TYPE keyType;			/* PKCS #11 key type */

	/* Function pointers */
	int ( *endFunction )( CONTEXT_INFO *contextInfoPtr );
	int ( *initKeyFunction )( CONTEXT_INFO *contextInfoPtr, const void *key, const int keyLength );
	int ( *generateKeyFunction )( CONTEXT_INFO *contextInfoPtr, const int keySizeBits );
	int ( *encryptFunction )( CONTEXT_INFO *contextInfoPtr, void *buffer, int length );
	int ( *decryptFunction )( CONTEXT_INFO *contextInfoPtr, void *buffer, int length );
	int ( *signFunction )( CONTEXT_INFO *contextInfoPtr, void *buffer, int length );
	int ( *sigCheckFunction )( CONTEXT_INFO *contextInfoPtr, void *buffer, int length );
	} MECHANISM_INFO;

static const MECHANISM_INFO mechanismInfo[] = {
	/* The handling of the RSA mechanism is a bit odd.  Almost everyone 
	   supports CKM_RSA_X_509 even though what's reported as being supported 
	   is CKM_RSA_PKCS, however the PKCS mechanism is often implemented in a 
	   buggy manner with all sorts of problems with handling the padding.  
	   The safest option would be to use the raw RSA one and do the padding 
	   ourselves, which means that it'll always be done right.  Since some 
	   implementations report raw RSA as being unavailable even though it's 
	   present, we detect it by checking for the PKCS mechanism but using 
	   raw RSA.  However, some implementations genuinely don't do raw RSA, so
	   the code fakes it by removing/adding dummy PKCS padding as required 
	   so that the caller sees raw RSA and the device sees PKCS.  This is a
	   compromise: We can handle the real (rather than faked) PKCS padding
	   ourselves and work around bugs in the output from other 
	   implementations, but we can't implement any new mechanisms other than
	   PKCS without support in the device.  The only implementation where 
	   even this causes problems is some versions of GemSAFE, which don't do 
	   raw RSA and also get the PKCS mechanism wrong */
	{ CKM_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN, CRYPT_ALGO_RSA, CRYPT_MODE_NONE, CKK_RSA,
	  NULL, rsaInitKey, rsaGenerateKey, 
	  rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify },
	{ CKM_DSA, CKM_DSA_KEY_PAIR_GEN, CRYPT_ALGO_DSA, CRYPT_MODE_NONE, CKK_DSA,
	  NULL, dsaInitKey, dsaGenerateKey, 
	  NULL, NULL, dsaSign, dsaVerify },
	{ CKM_DES_ECB, CRYPT_ERROR, CRYPT_ALGO_DES, CRYPT_MODE_ECB, CKK_DES,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptECB, cipherDecryptECB, NULL, NULL },
	{ CKM_DES_CBC, CRYPT_ERROR, CRYPT_ALGO_DES, CRYPT_MODE_CBC, CKK_DES,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptCBC, cipherDecryptCBC, NULL, NULL },
	{ CKM_DES3_ECB, CRYPT_ERROR, CRYPT_ALGO_3DES, CRYPT_MODE_ECB, CKK_DES3,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptECB, cipherDecryptECB, NULL, NULL },
	{ CKM_DES3_CBC, CRYPT_ERROR, CRYPT_ALGO_3DES, CRYPT_MODE_CBC, CKK_DES3,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptCBC, cipherDecryptCBC, NULL, NULL },
	{ CKM_IDEA_ECB, CRYPT_ERROR, CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, CKK_IDEA,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptECB, cipherDecryptECB, NULL, NULL },
	{ CKM_IDEA_CBC, CRYPT_ERROR, CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, CKK_IDEA,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptCBC, cipherDecryptCBC, NULL, NULL },
	{ CKM_CAST5_ECB, CRYPT_ERROR, CRYPT_ALGO_CAST, CRYPT_MODE_ECB, CKK_CAST5,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptECB, cipherDecryptECB, NULL, NULL },
	{ CKM_CAST5_CBC, CRYPT_ERROR, CRYPT_ALGO_CAST, CRYPT_MODE_CBC, CKK_CAST5,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptCBC, cipherDecryptCBC, NULL, NULL },
	{ CKM_RC2_ECB, CRYPT_ERROR, CRYPT_ALGO_RC2, CRYPT_MODE_ECB, CKK_RC2,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptECB, cipherDecryptECB, NULL, NULL },
	{ CKM_RC2_CBC, CRYPT_ERROR, CRYPT_ALGO_RC2, CRYPT_MODE_CBC, CKK_RC2,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptCBC, cipherDecryptCBC, NULL, NULL },
	{ CKM_RC4, CRYPT_ERROR, CRYPT_ALGO_RC4, CRYPT_MODE_OFB, CKK_RC4,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptOFB, cipherDecryptOFB, NULL, NULL },
	{ CKM_RC5_ECB, CRYPT_ERROR, CRYPT_ALGO_RC5, CRYPT_MODE_ECB, CKK_RC5,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptECB, cipherDecryptECB, NULL, NULL },
	{ CKM_RC5_CBC, CRYPT_ERROR, CRYPT_ALGO_RC5, CRYPT_MODE_CBC, CKK_RC5,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptCBC, cipherDecryptCBC, NULL, NULL },
	{ CKM_SKIPJACK_ECB64, CRYPT_ERROR, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_ECB, CKK_SKIPJACK,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptECB, cipherDecryptECB, NULL, NULL },
	{ CKM_SKIPJACK_CBC64, CRYPT_ERROR, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CBC, CKK_SKIPJACK,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptCBC, cipherDecryptCBC, NULL, NULL },
	{ CKM_SKIPJACK_CFB64, CRYPT_ERROR, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CFB, CKK_SKIPJACK,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptCFB, cipherDecryptCFB, NULL, NULL },
	{ CKM_SKIPJACK_OFB64, CRYPT_ERROR, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_OFB, CKK_SKIPJACK,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncryptOFB, cipherDecryptOFB, NULL, NULL },
	{ CRYPT_ERROR, CRYPT_ERROR, CRYPT_ALGO_NONE, CRYPT_MODE_NONE }
	};

/* Get a PKCS #11 mechanism type corresponding to a cryptlib algorithm and
   mode */

static CK_MECHANISM_TYPE getMechanism( const CRYPT_ALGO_TYPE cryptAlgo,
									   const CRYPT_MODE_TYPE cryptMode )
	{
	int i = 0;

	while( mechanismInfo[ i ].cryptAlgo != cryptAlgo && \
		   mechanismInfo[ i ].cryptAlgo != CRYPT_ERROR )
		i++;
	assert( i < sizeof( mechanismInfo ) / sizeof( MECHANISM_INFO ) && \
			mechanismInfo[ i ].cryptAlgo != CRYPT_ERROR );
	while( mechanismInfo[ i ].cryptMode != cryptMode && \
		   mechanismInfo[ i ].cryptAlgo != CRYPT_ERROR )
		i++;
	assert( i < sizeof( mechanismInfo ) / sizeof( MECHANISM_INFO ) && \
			mechanismInfo[ i ].cryptAlgo != CRYPT_ERROR );

	return( mechanismInfo[ i ].mechanism );
	}

/* Query a given capability for a device and fill out a capability info
   record for it if present */

static CAPABILITY_INFO *getCapability( const DEVICE_INFO *deviceInfo,
									   const MECHANISM_INFO *mechanismInfoPtr )
	{
	VARIABLE_CAPABILITY_INFO *capabilityInfo;
	CK_MECHANISM_INFO mechanismInfo;
	CK_RV status;
	const CRYPT_ALGO_TYPE cryptAlgo = mechanismInfoPtr->cryptAlgo;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	int hardwareOnly, i;

	/* Get the information for this mechanism.  Since many PKCS #11 drivers
	   implement some of their capabilities using God knows what sort of 
	   software implementation, we provide the option to skip emulated 
	   mechanisms if required */
	status = C_GetMechanismInfo( pkcs11Info->slotID, 
								 mechanismInfoPtr->mechanism,
								 &mechanismInfo );
	if( status != CKR_OK )
		return( NULL );
	krnlSendMessage( deviceInfo->ownerHandle, IMESSAGE_GETATTRIBUTE, 
					 &hardwareOnly, CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY );
	if( hardwareOnly && !( mechanismInfo.flags & CKF_HW ) )
		return( NULL );

	/* Copy across the template for this capability */
	if( ( capabilityInfo = clAlloc( "getCapability", \
									sizeof( CAPABILITY_INFO ) ) ) == NULL )
		return( NULL );
	for( i = 0; \
		 capabilityTemplates[ i ].cryptAlgo != mechanismInfoPtr->cryptAlgo && \
		 capabilityTemplates[ i ].cryptAlgo != CRYPT_ERROR; \
		 i++ );
	assert( i < sizeof( capabilityTemplates ) / sizeof( CAPABILITY_INFO ) && \
			capabilityTemplates[ i ].cryptAlgo != CRYPT_ERROR );
	memcpy( capabilityInfo, &capabilityTemplates[ i ],
			sizeof( CAPABILITY_INFO ) );

	/* Set up the keysize information if there's anything useful available */
	if( keysizeValid( mechanismInfoPtr->cryptAlgo ) )
		{
		int minKeySize = ( int ) mechanismInfo.ulMinKeySize;
		int maxKeySize = ( int ) mechanismInfo.ulMaxKeySize;

		/* Adjust the key size to bytes and make sure that all values are 
		   consistent.  Some implementations report silly lower bounds (e.g. 
		   1-bit RSA, "You naughty minKey") so we adjust them to a sane value 
		   if necessary.  We also limit the maximum key size to match the
		   cryptlib native max.key size, both for consistency and because
		   cryptlib performs buffer allocation based on the maximum native
		   buffer size */
		if( !keysizeBytes( mechanismInfoPtr->cryptAlgo ) )
			{
			minKeySize = bitsToBytes( minKeySize );
			maxKeySize = bitsToBytes( maxKeySize );
			}
		if( minKeySize > capabilityInfo->minKeySize )
			capabilityInfo->minKeySize = minKeySize;
		if( capabilityInfo->keySize < capabilityInfo->minKeySize )
			capabilityInfo->keySize = capabilityInfo->minKeySize;
		capabilityInfo->maxKeySize = min( maxKeySize, 
										  capabilityInfo->maxKeySize );
		if( capabilityInfo->maxKeySize < capabilityInfo->minKeySize )
			{
			/* Serious braindamage in the driver, we'll just have to make
			   a sensible guess */
			assert( NOTREACHED );
			capabilityInfo->maxKeySize = \
				( mechanismInfoPtr->cryptAlgo == CRYPT_ALGO_RSA || \
				  isDlpAlgo( mechanismInfoPtr->cryptAlgo ) ) ? 128 : 16;
			}
		if( capabilityInfo->keySize > capabilityInfo->maxKeySize )
			capabilityInfo->keySize = capabilityInfo->maxKeySize;
		capabilityInfo->endFunction = genericEndFunction;
		}

	/* Set up the device-specific handlers */
	capabilityInfo->getInfoFunction = getInfo;
	if( mechanismInfoPtr->cryptAlgo != CRYPT_ALGO_RSA && \
		mechanismInfoPtr->cryptAlgo != CRYPT_ALGO_DSA )
		capabilityInfo->initKeyParamsFunction = initKeyParams;
	capabilityInfo->endFunction = mechanismInfoPtr->endFunction;
	capabilityInfo->initKeyFunction = mechanismInfoPtr->initKeyFunction;
	if( mechanismInfo.flags & CKF_GENERATE_KEY_PAIR )
		capabilityInfo->generateKeyFunction = mechanismInfoPtr->generateKeyFunction;
	if( mechanismInfo.flags & CKF_SIGN )
		capabilityInfo->signFunction = mechanismInfoPtr->signFunction;
	if( mechanismInfo.flags & CKF_VERIFY )
		capabilityInfo->sigCheckFunction = mechanismInfoPtr->sigCheckFunction;
	if( mechanismInfo.flags & CKF_ENCRYPT )
		if( mechanismInfoPtr->cryptMode == CRYPT_MODE_OFB )
			/* Stream ciphers have an implicit mode of OFB */
			capabilityInfo->encryptOFBFunction = mechanismInfoPtr->encryptFunction;
		else
			capabilityInfo->encryptFunction = mechanismInfoPtr->encryptFunction;
	if( mechanismInfo.flags & CKF_DECRYPT )
		if( mechanismInfoPtr->cryptMode == CRYPT_MODE_OFB )
			/* Stream ciphers have an implicit mode of OFB */
			capabilityInfo->decryptOFBFunction = mechanismInfoPtr->decryptFunction;
		else
			capabilityInfo->decryptFunction = mechanismInfoPtr->decryptFunction;

	/* PKC keygen capabilities are generally present as separate mechanisms,
	   sometimes CKF_GENERATE_KEY_PAIR is set for the main mechanism and
	   sometimes it's set for the separate one so if it isn't present in the
	   main one we check the alternative one */
	if( !( mechanismInfo.flags & CKF_GENERATE_KEY_PAIR ) && \
		( mechanismInfoPtr->keygenMechanism != CRYPT_ERROR ) )
		{
		status = C_GetMechanismInfo( pkcs11Info->slotID, 
									 mechanismInfoPtr->keygenMechanism,
									 &mechanismInfo );
		if( status == CKR_OK && \
			( mechanismInfo.flags & CKF_GENERATE_KEY_PAIR ) && \
			( !hardwareOnly || ( mechanismInfo.flags & CKF_HW ) ) )
			/* Some tinkertoy tokens don't implement key generation in 
			   hardware but instead do it on the host PC (!!!) and load the
			   key into the token afterwards, so we have to perform another 
			   check here to make sure they're doing things right */
			capabilityInfo->generateKeyFunction = \
									mechanismInfoPtr->generateKeyFunction;
		}

	/* If it's not a conventional encryption algo, we're done */
	if( mechanismInfoPtr->cryptAlgo < CRYPT_ALGO_FIRST_CONVENTIONAL || \
		mechanismInfoPtr->cryptAlgo > CRYPT_ALGO_LAST_CONVENTIONAL )
		return( ( CAPABILITY_INFO * ) capabilityInfo );

	/* PKCS #11 handles encryption modes by defining a separate mechanism for
	   each one.  In order to enumerate all the modes available for a 
	   particular algorithm we check for each mechanism in turn and set up 
	   the appropriate function pointers if it's available */
	capabilityInfo->paramKeyType = mechanismInfoPtr->keyType;
	for( mechanismInfoPtr++; mechanismInfoPtr->cryptAlgo == cryptAlgo; 
		 mechanismInfoPtr++ )
		{
		/* There's a different form of the existing mechanism available,
		   check whether the driver implements it */
		status = C_GetMechanismInfo( pkcs11Info->slotID, 
									 mechanismInfoPtr->mechanism,
									 &mechanismInfo );
		if( status != CKR_OK )
			continue;

		/* Set up the pointer for the appropriate encryption mode */
		switch( mechanismInfoPtr->cryptMode )
			{
			case CRYPT_MODE_CBC:
				if( mechanismInfo.flags & CKF_ENCRYPT )
					capabilityInfo->encryptCBCFunction = \
										mechanismInfoPtr->encryptFunction;
				if( mechanismInfo.flags & CKF_DECRYPT )
					capabilityInfo->decryptCBCFunction = \
										mechanismInfoPtr->decryptFunction;
				break;
			case CRYPT_MODE_CFB:
				if( mechanismInfo.flags & CKF_ENCRYPT )
					capabilityInfo->encryptCFBFunction = \
										mechanismInfoPtr->encryptFunction;
				if( mechanismInfo.flags & CKF_DECRYPT )
					capabilityInfo->decryptCFBFunction = \
										mechanismInfoPtr->decryptFunction;
				break;
			case CRYPT_MODE_OFB:
				if( mechanismInfo.flags & CKF_ENCRYPT )
					capabilityInfo->encryptOFBFunction = \
										mechanismInfoPtr->encryptFunction;
				if( mechanismInfo.flags & CKF_DECRYPT )
					capabilityInfo->decryptOFBFunction = \
										mechanismInfoPtr->decryptFunction;
				break;

			default:
				assert( NOTREACHED );
			}
		}

	return( ( CAPABILITY_INFO * ) capabilityInfo );
	}

/* Set the capability information based on device capabilities.  Since
   PKCS #11 devices can have assorted capabilities (and can vary depending
   on what's plugged in), we have to build this up on the fly rather than
   using a fixed table like the built-in capabilities */

static void freeCapabilities( DEVICE_INFO *deviceInfo )
	{
	CAPABILITY_INFO *capabilityInfoPtr = \
				( CAPABILITY_INFO * ) deviceInfo->capabilityInfo;

	/* If the list was empty, return now */
	if( capabilityInfoPtr == NULL )
		return;
	deviceInfo->capabilityInfo = NULL;

	while( capabilityInfoPtr != NULL )
		{
		CAPABILITY_INFO *itemToFree = capabilityInfoPtr;

		capabilityInfoPtr = capabilityInfoPtr->next;
		zeroise( itemToFree, sizeof( CAPABILITY_INFO ) );
		clFree( "freeCapabilities", itemToFree );
		}
	}

static int getCapabilities( DEVICE_INFO *deviceInfo )
	{
	CAPABILITY_INFO *capabilityListTail = \
				( CAPABILITY_INFO * ) deviceInfo->capabilityInfo;
	int i;

	assert( sizeof( CAPABILITY_INFO ) == sizeof( VARIABLE_CAPABILITY_INFO ) );

	/* Add capability information for each recognised mechanism type */
	for( i = 0; mechanismInfo[ i ].mechanism != CRYPT_ERROR; i++ )
		{
		CAPABILITY_INFO *newCapability;
		const CRYPT_ALGO_TYPE cryptAlgo = mechanismInfo[ i ].cryptAlgo;

		/* If the assertion below triggers then the PKCS #11 driver is 
		   broken since it's returning inconsistent information such as 
		   illegal key length data, conflicting algorithm information, etc 
		   etc.  This assertion is included here to detect buggy drivers 
		   early on rather than forcing users to step through the PKCS #11 
		   glue code to find out why an operation is failing.
		   
		   Because some tinkertoy implementations support only the bare 
		   minimum functionality (e.g.RSA private key ops and nothing else),
		   we allow asymmetric functionality for PKCs */
		newCapability = getCapability( deviceInfo, &mechanismInfo[ i ] );
		if( newCapability == NULL )
			continue;
		assert( capabilityInfoOK( newCapability, 
					( newCapability->cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
					  newCapability->cryptAlgo <= CRYPT_ALGO_LAST_PKC ) ? \
					  TRUE : FALSE ) );
		if( deviceInfo->capabilityInfo == NULL )
			deviceInfo->capabilityInfo = newCapability;
		else
			capabilityListTail->next = newCapability;
		capabilityListTail = newCapability;

		/* Since there may be alternative mechanisms to the current one 
		   defined, we have to skip mechanisms until we find a ones for a
		   new algorithm */
		while( mechanismInfo[ i + 1 ].cryptAlgo == cryptAlgo )
			i++;
		}

	return( ( deviceInfo->capabilityInfo == NULL ) ? CRYPT_ERROR : CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Mechanisms supported by PKCS #11 devices.  These are actually cryptlib 
   native mechanisms (support of the various mechanisms in devices is too 
   patchy to rely on, see for example the comments about PKCS vs.raw RSA
   mechanisms elsewhere), but not the full set supported by the system 
   device since functions like private key export aren't available.  The 
   list is sorted in order of frequency of use in order to make lookups a 
   bit faster */

static const FAR_BSS MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
	{ MESSAGE_DEV_EXPORT, MECHANISM_PKCS1, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PKCS1, ( MECHANISM_FUNCTION ) importPKCS1 },
	{ MESSAGE_DEV_SIGN, MECHANISM_PKCS1, ( MECHANISM_FUNCTION ) signPKCS1 },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_PKCS1, ( MECHANISM_FUNCTION ) sigcheckPKCS1 },
	{ MESSAGE_DEV_EXPORT, MECHANISM_PKCS1_RAW, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PKCS1_RAW, ( MECHANISM_FUNCTION ) importPKCS1 },
#ifdef USE_PGP
	{ MESSAGE_DEV_EXPORT, MECHANISM_PKCS1_PGP, ( MECHANISM_FUNCTION ) exportPKCS1PGP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PKCS1_PGP, ( MECHANISM_FUNCTION ) importPKCS1PGP },
#endif /* USE_PGP */
	{ MESSAGE_DEV_EXPORT, MECHANISM_CMS, ( MECHANISM_FUNCTION ) exportCMS },
	{ MESSAGE_DEV_IMPORT, MECHANISM_CMS, ( MECHANISM_FUNCTION ) importCMS },
	{ MESSAGE_DEV_DERIVE, MECHANISM_PKCS5, ( MECHANISM_FUNCTION ) derivePKCS5 },
#if defined( USE_PGP ) || defined( USE_PGPKEYS )
	{ MESSAGE_DEV_DERIVE, MECHANISM_PGP, ( MECHANISM_FUNCTION ) derivePGP },
#endif /* USE_PGP || USE_PGPKEYS */
#ifdef USE_SSL
	{ MESSAGE_DEV_DERIVE, MECHANISM_SSL, ( MECHANISM_FUNCTION ) deriveSSL },
	{ MESSAGE_DEV_DERIVE, MECHANISM_TLS, ( MECHANISM_FUNCTION ) deriveTLS },
#endif /* USE_SSL */
#ifdef USE_CMP
	{ MESSAGE_DEV_DERIVE, MECHANISM_CMP, ( MECHANISM_FUNCTION ) deriveCMP },
#endif /* USE_CMP */
#ifdef USE_PKCS12
	{ MESSAGE_DEV_DERIVE, MECHANISM_PKCS12, ( MECHANISM_FUNCTION ) derivePKCS12 },
#endif /* USE_PKCS12 */
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

/* Set up the function pointers to the device methods */

int setDevicePKCS11( DEVICE_INFO *deviceInfo, const char *name, 
					 const int nameLength )
	{
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
#ifdef DYNAMIC_LOAD
	int i, driverNameLength = nameLength;
#else
	UNUSED( name );
#endif /* DYNAMIC_LOAD */

	/* Make sure that the PKCS #11 driver DLL's are loaded */
	if( !pkcs11Initialised )
		return( CRYPT_ERROR_OPEN );

#ifdef DYNAMIC_LOAD
	/* Check whether there's a token name appended to the driver name */
	for( i = 1; i < nameLength - 1; i++ )
		if( name[ i ] == ':' && name[ i + 1 ] == ':' )
			{
			driverNameLength = i;
			break;
			}

	/* If we're auto-detecting the device, use the first one that we find */
	if( driverNameLength == 12 && \
		!strnicmp( "[Autodetect]", name, driverNameLength ) )
		{
		if( !pkcs11InfoTbl[ 0 ].name[ 0 ] )
			return( CRYPT_ERROR_NOTFOUND );
		pkcs11Info->deviceNo = 0;
		}
	else
		{
		/* Try and find the driver based on its name */
		for( i = 0; i < MAX_PKCS11_DRIVERS; i++ )
			if( !strnicmp( pkcs11InfoTbl[ i ].name, name, driverNameLength ) )
				break;
		if( i == MAX_PKCS11_DRIVERS )
			return( CRYPT_ERROR_NOTFOUND );
		pkcs11Info->deviceNo = i;
		}
#endif /* DYNAMIC_LOAD */

	deviceInfo->initFunction = initFunction;
	deviceInfo->shutdownFunction = shutdownFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->getItemFunction = getItemFunction;
	deviceInfo->setItemFunction = setItemFunction;
	deviceInfo->deleteItemFunction = deleteItemFunction;
	deviceInfo->getRandomFunction = getRandomFunction;
	deviceInfo->mechanismFunctions = mechanismFunctions;

	return( CRYPT_OK );
	}
#endif /* USE_PKCS11 */
