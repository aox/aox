#define USE_CRYPTOAPI
void *hCertStore;	// CAPI dev-specific entry for device_info */

/****************************************************************************
*																			*
*							cryptlib CryptoAPI Routines						*
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

/* Occasionally we need to read things into host memory from a device in a
   manner that can't be handled by a dynBuf since the data is coming from a
   device rather than a cryptlib object.  The following value defines the 
   maximum size of the on-stack buffer, if the data is larger than this we 
   dynamically allocate the buffer (this almost never occurs) */

#define MAX_BUFFER_SIZE			1024

/* Prototypes for functions in cryptcap.c */

const void FAR_BSS *findCapabilityInfo( const void FAR_BSS *capabilityInfoPtr,
										const CRYPT_ALGO_TYPE cryptAlgo );

#ifdef USE_CRYPTOAPI

/* The following define is needed to enable crypto functions in the include
   file.  This would probably be defined by the compiler since it's not 
   defined in any header file, but it doesn't seem to be enabled by 
   default */

#ifndef _WIN32_WINNT
  #define _WIN32_WINNT	0x0500
#endif /* _WIN32_WINNT */

/* cryptlib.h includes a trap for inclusion of wincrypt.h before cryptlib.h
   which results in a compiler error if both files are included.  To disable 
   this, we need to undefine the CRYPT_MODE_ECB defined in cryptlib.h */

#undef CRYPT_MODE_ECB

#include <wincrypt.h>

/* CryptoAPI uses the same mode names as cryptlib but different values, 
   fortunately this is done with #defines so we can remove them at this
   point */

#undef CRYPT_MODE_ECB
#undef CRYPT_MODE_CBC
#undef CRYPT_MODE_CFB
#undef CRYPT_MODE_OFB

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on some
   systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hCryptoAPI = NULL_HINSTANCE;
static HINSTANCE hAdvAPI32 = NULL_HINSTANCE;

typedef BOOL ( WINAPI *CERTADDENCODEDCERTIFICATETOSTORE )( HCERTSTORE hCertStore,
					DWORD dwCertEncodingType, const BYTE *pbCertEncoded, 
					DWORD cbCertEncoded, DWORD dwAddDisposition, 
					PCCERT_CONTEXT *ppCertContext );
typedef BOOL ( WINAPI *CERTCLOSESTORE )( HCERTSTORE hCertStore, DWORD dwFlags );
typedef BOOL ( WINAPI *CERTDELETECERTIFICATEFROMSTORE )( PCCERT_CONTEXT pCertContext );
typedef PCCERT_CONTEXT ( WINAPI *CERTFINDCERTIFICATEINSTORE )( HCERTSTORE hCertStore,
					DWORD dwCertEncodingType, DWORD dwFindFlags, 
					DWORD dwFindType, const void *pvFindPara, 
					PCCERT_CONTEXT pPrevCertContext );
typedef BOOL ( WINAPI *CERTFREECERTIFICATECONTEXT )( PCCERT_CONTEXT pCertContext );
typedef PCCERT_CONTEXT ( WINAPI *CERTGETSUBJECTCERTIFICATEFROMSTORE )( HCERTSTORE hCertStore,
					DWORD dwCertEncodingType, PCERT_INFO pCertId );
typedef HCERTSTORE ( WINAPI *CERTOPENSTORE )( LPCSTR lpszStoreProvider,
					 DWORD dwEncodingType, HCRYPTPROV hCryptProv, 
					 DWORD dwFlags, const void *pvPara );

typedef BOOL ( WINAPI *CRYPTACQUIRECONTEXTA )( HCRYPTPROV *phProv, LPCSTR pszContainer,
					LPCSTR pszProvider, DWORD dwProvType, DWORD dwFlags );
typedef BOOL ( WINAPI *CRYPTDECRYPT )( HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final,
					DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen );
typedef BOOL ( WINAPI *CRYPTDESTROYHASH )( HCRYPTHASH hHash );
typedef BOOL ( WINAPI *CRYPTDESTROYKEY )( HCRYPTKEY hKey );
typedef BOOL ( WINAPI *CRYPTENCRYPT )( HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final,
					DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen );
typedef BOOL ( WINAPI *CRYPTEXPORTKEY )( HCRYPTKEY hKey, HCRYPTKEY hExpKey,
					DWORD dwBlobType, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen );
typedef BOOL ( WINAPI *CRYPTGENKEY )( HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags,
					HCRYPTKEY *phKey );
typedef BOOL ( WINAPI *CRYPTGENRANDOM )( HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer );
typedef BOOL ( WINAPI *CRYPTGETPROVPARAM )( HCRYPTPROV hProv, DWORD dwParam, 
					BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags );
typedef BOOL ( WINAPI *CRYPTHASHDATA )( HCRYPTHASH hHash, BYTE *pbData, DWORD dwDataLen,
					DWORD dwFlags );
typedef BOOL ( WINAPI *CRYPTIMPORTKEY )( HCRYPTPROV hProv, CONST BYTE *pbData,
					DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey );
typedef BOOL ( WINAPI *CRYPTRELEASECONTEXT )( HCRYPTPROV hProv, DWORD dwFlags );
typedef BOOL ( WINAPI *CRYPTSETKEYPARAM )( HCRYPTKEY hKey, DWORD dwParam, 
					BYTE *pbData, DWORD dwFlags );

static CERTADDENCODEDCERTIFICATETOSTORE pCertAddEncodedCertificateToStore = NULL;
static CERTDELETECERTIFICATEFROMSTORE pCertDeleteCertificateFromStore = NULL;
static CERTCLOSESTORE pCertCloseStore = NULL;
static CERTFINDCERTIFICATEINSTORE pCertFindCertificateInStore = NULL;
static CERTFREECERTIFICATECONTEXT pCertFreeCertificateContext = NULL;
static CERTGETSUBJECTCERTIFICATEFROMSTORE pCertGetSubjectCertificateFromStore = NULL;
static CERTOPENSTORE pCertOpenStore = NULL;

static CRYPTACQUIRECONTEXTA pCryptAcquireContextA = NULL;
static CRYPTDECRYPT pCryptDecrypt = NULL;
static CRYPTDESTROYHASH pCryptDestroyHash = NULL;
static CRYPTDESTROYKEY pCryptDestroyKey = NULL;
static CRYPTENCRYPT pCryptEncrypt = NULL;
static CRYPTEXPORTKEY pCryptExportKey = NULL;
static CRYPTGENKEY pCryptGenKey = NULL;
static CRYPTGENRANDOM pCryptGenRandom = NULL;
static CRYPTGETPROVPARAM pCryptGetProvParam = NULL;
static CRYPTHASHDATA pCryptHashData = NULL;
static CRYPTIMPORTKEY pCryptImportKey = NULL;
static CRYPTRELEASECONTEXT pCryptReleaseContext = NULL;
static CRYPTSETKEYPARAM pCryptSetKeyParam = NULL;

/* Dynamically load and unload any necessary DBMS libraries */

int deviceInitCryptoAPI( void )
	{
	/* If the CryptoAPI module is already linked in, don't do anything */
	if( hCryptoAPI != NULL_HINSTANCE )
		return( CRYPT_OK );

	/* Obtain handles to the modules containing the CryptoAPI functions */
	if( ( hAdvAPI32 = GetModuleHandle( "AdvAPI32.DLL" ) ) == NULL )
		return( CRYPT_ERROR );
	if( ( hCryptoAPI = LoadLibrary( "Crypt32.dll" ) ) == NULL_HINSTANCE )
		return( CRYPT_ERROR );

	/* Get pointers to the crypt functions */
	pCryptAcquireContextA = ( CRYPTACQUIRECONTEXTA ) GetProcAddress( hAdvAPI32, "CryptAcquireContextA" );
	pCryptDecrypt = ( CRYPTDECRYPT ) GetProcAddress( hAdvAPI32, "CryptDecrypt" );
	pCryptDestroyHash = ( CRYPTDESTROYHASH ) GetProcAddress( hAdvAPI32, "CryptDestroyHash" );
	pCryptDestroyKey = ( CRYPTDESTROYKEY ) GetProcAddress( hAdvAPI32, "CryptDestroyKey" );
	pCryptEncrypt = ( CRYPTENCRYPT ) GetProcAddress( hAdvAPI32, "CryptEncrypt" );
	pCryptExportKey = ( CRYPTEXPORTKEY ) GetProcAddress( hAdvAPI32, "CryptExportKey" );
	pCryptGenKey = ( CRYPTGENKEY ) GetProcAddress( hAdvAPI32, "CryptGenKey" );
	pCryptGenRandom = ( CRYPTGENRANDOM ) GetProcAddress( hAdvAPI32, "CryptGenRandom" );
	pCryptGetProvParam = ( CRYPTGETPROVPARAM ) GetProcAddress( hAdvAPI32, "CryptGetProvParam" );
	pCryptHashData = ( CRYPTHASHDATA ) GetProcAddress( hAdvAPI32, "CryptHashData" );
	pCryptImportKey = ( CRYPTIMPORTKEY ) GetProcAddress( hAdvAPI32, "CryptImportKey" );
	pCryptReleaseContext = ( CRYPTRELEASECONTEXT ) GetProcAddress( hAdvAPI32, "CryptReleaseContext" );
	pCryptSetKeyParam = ( CRYPTSETKEYPARAM ) GetProcAddress( hAdvAPI32, "CryptSetKeyParam" );

	/* Get pointers to the cert functions */
	pCertAddEncodedCertificateToStore = ( CERTADDENCODEDCERTIFICATETOSTORE ) GetProcAddress( hCryptoAPI, "CertAddEncodedCertificateToStore" );
	pCertDeleteCertificateFromStore = ( CERTDELETECERTIFICATEFROMSTORE ) GetProcAddress( hCryptoAPI, "CertDeleteCertificateFromStore" );
	pCertCloseStore = ( CERTCLOSESTORE ) GetProcAddress( hCryptoAPI, "CertCloseStore" );
	pCertFindCertificateInStore = ( CERTFINDCERTIFICATEINSTORE ) GetProcAddress( hCryptoAPI, "CertFindCertificateInStore" );
	pCertFreeCertificateContext = ( CERTFREECERTIFICATECONTEXT )  GetProcAddress( hCryptoAPI, "CertFreeCertificateContext" );
	pCertGetSubjectCertificateFromStore = ( CERTGETSUBJECTCERTIFICATEFROMSTORE ) GetProcAddress( hCryptoAPI, "CertGetSubjectCertificateFromStore" );
	pCertOpenStore = ( CERTOPENSTORE ) GetProcAddress( hCryptoAPI, "CertOpenStore" );

	/* Make sure that we got valid pointers for every CryptoAPI function */
	if( pCertAddEncodedCertificateToStore == NULL || 
		pCertDeleteCertificateFromStore == NULL ||
		pCertCloseStore == NULL || pCertFindCertificateInStore == NULL ||
		pCertFreeCertificateContext == NULL || 
		pCertGetSubjectCertificateFromStore == NULL || pCertOpenStore == NULL || 
		pCryptAcquireContextA == NULL || pCryptDecrypt == NULL ||
		pCryptEncrypt == NULL || pCryptExportKey == NULL || 
		pCryptDestroyHash == NULL || pCryptDestroyKey == NULL || 
		pCryptGenKey == NULL || pCryptGenRandom == NULL || 
		pCryptGetProvParam == NULL || pCryptHashData == NULL || 
		pCryptImportKey == NULL || pCryptReleaseContext == NULL || 
		pCryptSetKeyParam == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hCryptoAPI );
		hCryptoAPI = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

void deviceEndCryptoAPI( void )
	{
	if( hCryptoAPI != NULL_HINSTANCE )
		FreeLibrary( hCryptoAPI );
	hCryptoAPI = NULL_HINSTANCE;
	}

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a CryptoAPI-specific error to a cryptlib error */

static int mapError( CRYPTOAPI_INFO *cryptoapiInfo, const int defaultError )
	{
	const DWORD errorCode = GetLastError();

	cryptoapiInfo->errorCode = ( int ) errorCode;
	FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM, NULL, errorCode, 0,
				   cryptoapiInfo->errorMessage, MAX_ERRMSG_SIZE - 1, 0 );
	switch( errorCode )
		{
		case CRYPT_E_UNKNOWN_ALGO:
			return( CRYPT_ERROR_NOTAVAIL );

		case ERROR_BUSY:
			return( CRYPT_ERROR_TIMEOUT );

		case ERROR_MORE_DATA:
			return( CRYPT_ERROR_OVERFLOW );

		case ERROR_NO_MORE_ITEMS:
			return( CRYPT_ERROR_COMPLETE );

		case CRYPT_E_EXISTS:
		case NTE_EXISTS:
			return( CRYPT_ERROR_DUPLICATE );

		case ERROR_NOT_ENOUGH_MEMORY:
		case NTE_NO_MEMORY:
			return( CRYPT_ERROR_MEMORY );

		case CRYPT_E_SECURITY_SETTINGS:
		case NTE_PERM:
			return( CRYPT_ERROR_PERMISSION );

		case NTE_BAD_SIGNATURE:
			return( CRYPT_ERROR_SIGNATURE );

		case CRYPT_E_NO_MATCH:
		case CRYPT_E_NOT_FOUND:
		case NTE_KEYSET_NOT_DEF:
		case NTE_NOT_FOUND:
		case NTE_PROV_DLL_NOT_FOUND:
		case NTE_PROV_TYPE_NO_MATCH:
		case NTE_PROV_TYPE_NOT_DEF:
			return( CRYPT_ERROR_NOTFOUND );
		}

	return( defaultError );
	}

static int mapDeviceError( CONTEXT_INFO *contextInfoPtr, const int defaultError )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	int status;

	/* Get the device associated with this context, set the error information
	   in it, and exit */
	status = krnlSendMessage( contextInfoPtr->objectHandle, IMESSAGE_GETDEPENDENT, 
							  &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( status ) )
		status = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( void ** ) &deviceInfo, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	status = mapError( deviceInfo->deviceCryptoAPI, defaultError );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( status );
	}

/* Create the special-case RSA key with e=1 needed to allow direct key 
   import and export */

static int createExportKey( const HCRYPTPROV hProv, HCRYPTKEY *hPrivateKey, 
							int *privateKeySize )
	{
	BLOBHEADER *blobHeaderPtr;
	RSAPUBKEY *pubKeyPtr;
	BYTE keyBlob[ 1024 ], *keyBlobPtr;
	int bitLen16, keyBlobLen = 1024, status;

	/* Generate a private key and export it as a private key blob:

		Ofs	Value
		  0	PUBLICKEYSTRUC publickeystruc {
			  0	BYTE bType;
			  1	BYTE bVersion;
			  2 WORD reserved;
			  4	ALG_ID aiKeyAlg; }
		  8	RSAPUBKEY rsapubkey {
			  8 DWORD magic;
			 12	DWORD bitlen;
			 16	DWORD pubexp; }
		 20	BYTE modulus[ rsapubkey.bitlen / 8 ];
			BYTE prime1[ rsapubkey.bitlen / 16 ];
			BYTE prime2[ rsapubkey.bitlen / 16 ];
			BYTE exponent1[ rsapubkey.bitlen / 16 ];
			BYTE exponent2[ rsapubkey.bitlen / 16 ];
			BYTE coefficient[ rsapubkey.bitlen / 16 ];
			BYTE privateExponent[ rsapubkey.bitlen / 8 ]; */
	if( !pCryptGenKey( hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, hPrivateKey ) || \
		!pCryptExportKey( *hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyBlob, &keyBlobLen ) || \
		!pCryptDestroyKey( *hPrivateKey ) )
		return( CRYPT_ERROR );

	/* Perform a general sanity check on the returned data */
	blobHeaderPtr = ( BLOBHEADER * ) keyBlob;
	if( blobHeaderPtr->bType != PRIVATEKEYBLOB || \
		blobHeaderPtr->bVersion != 2 || \
		blobHeaderPtr->aiKeyAlg != CALG_RSA_KEYX )
		{
		pCryptDestroyKey( *hPrivateKey );
		return( CRYPT_ERROR );
		}

	/* Set the public exponent to 1 (little-endian 32-bit value) and skip to 
	   the private exponents */
	pubKeyPtr = ( RSAPUBKEY * ) ( keyBlob + 8 );
	bitLen16 = ( pubKeyPtr->bitlen / 16 );
	pubKeyPtr->pubexp = 1;
	keyBlobPtr = keyBlob + 20 + ( pubKeyPtr->bitlen / 8 ) + bitLen16 + bitLen16;

	/* Set the two exponents to 1 */
	*keyBlobPtr++ = 1;
	memset( keyBlobPtr, 0, bitLen16 - 1 );
	keyBlobPtr += bitLen16 - 1;
	*keyBlobPtr++ = 1;
	memset( keyBlobPtr, 0, bitLen16 - 1 );
	keyBlobPtr += bitLen16 - 1;

	/* Set the private exponent to 1 */
	keyBlobPtr += bitLen16;		/* Skip coefficient */
	*keyBlobPtr++ = 1;
	memset( keyBlobPtr, 0, bitLen16 - 1 );
	keyBlobPtr += bitLen16 - 1;

	/* Finally, import the hacked key and clean up */
	status = pCryptImportKey( hProv, keyBlob, keyBlobLen, 0, 0, hPrivateKey );
	if( status )
		*privateKeySize = pubKeyPtr->bitlen / 8;
	else
		*hPrivateKey = 0;
	zeroise( keyBlob, keyBlobLen );

	return( status ? CRYPT_OK : CRYPT_ERROR );
	}

/* Import a raw session key using the exponent-one RSA key */

static int importPlainKey( const HCRYPTPROV hProv, 
						   const HCRYPTKEY hPrivateKey, 
						   const privateKeySize, HCRYPTKEY *hSessionKey, 
						   const CRYPT_ALGO_TYPE cryptAlgo, const BYTE *keyData, 
						   const int keyDataSize )
	{
	BLOBHEADER *blobHeaderPtr;
	BYTE keyBlob[ 1024 ], *keyBlobPtr;
	struct {
		const CRYPT_ALGO_TYPE cryptAlgo;
		const ALG_ID algID;
		} algoMap[] = {
		{ CRYPT_ALGO_DES, CALG_DES },
		{ CRYPT_ALGO_3DES, CALG_3DES },
		{ CRYPT_ALGO_RC2, CALG_RC2 },
		{ CRYPT_ALGO_RC4, CALG_RC4 },
		{ CRYPT_ALGO_SKIPJACK, CALG_SKIPJACK },
		{ CRYPT_ALGO_NONE, 0 }
		};
	ALG_ID algID;
	DWORD *dwPtr;
	const int blobSize = sizeof( BLOBHEADER ) + sizeof( ALG_ID ) + privateKeySize;
	int i, status;

	for( i = 0; algoMap[ i ].cryptAlgo != CRYPT_ALGO_NONE; i++ )
		if( algoMap[ i ].cryptAlgo == cryptAlgo )
			break;
	if( algoMap[ i ].cryptAlgo == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );
	algID = algoMap[ i ].algID;

	/* Set up a SIMPLEBLOB:

		Ofs	Value
		  0	PUBLICKEYSTRUC publickeystruc {
			  0	BYTE bType;
			  1	BYTE bVersion;
			  2 WORD reserved;
			  4	ALG_ID aiKeyAlg; }
		  8	ALG_ID algid;
		 12	BYTE encryptedkey[ rsapubkey.bitlen/8 ]; */
	memset( keyBlob, 0, 1024 );

	/* Set up the PUBLICKEYSTRUC part of the blob */
	blobHeaderPtr = ( BLOBHEADER * ) keyBlob;
    blobHeaderPtr->bType = SIMPLEBLOB;
	blobHeaderPtr->bVersion = 2;
	blobHeaderPtr->aiKeyAlg = algID;

	/* Set up the private-key algorithm ID */
	dwPtr = ( DWORD * )( keyBlob + 8 );
	*dwPtr = CALG_RSA_KEYX;

	/* Store the key as byte-reversed PKCS #1 padded data (or at least close 
	   enough to it to work for the import) */
	keyBlobPtr = keyBlob + 12;
	for( i = keyDataSize - 1; i >= 0; i-- )
		*keyBlobPtr++ = keyData[ i ];
	*keyBlobPtr++ = 0;
	memset( keyBlobPtr, 2, privateKeySize - ( keyDataSize + 2 ) );

	/* Import the key from the faked PKCS #1 wrapped form */
	status = pCryptImportKey( hProv, keyBlob, blobSize, hPrivateKey, 0, hSessionKey );
	zeroise( keyBlob, blobSize );

	return( status ? CRYPT_OK : CRYPT_ERROR_FAILED );
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
	CRYPTOAPI_INFO *cryptoapiInfo = deviceInfo->deviceCryptoAPI;

	/* Log out and close the session with the device */
	if( deviceInfo->flags & DEVICE_LOGGEDIN )
		{
		if( cryptoapiInfo->hPrivateKey )
			pCryptDestroyKey( cryptoapiInfo->hPrivateKey );
		pCryptReleaseContext( cryptoapiInfo->hProv, 0 );
		}
	cryptoapiInfo->hProv = CRYPT_ERROR;
	deviceInfo->flags &= ~( DEVICE_ACTIVE | DEVICE_LOGGEDIN );

	/* Free the device capability information */
	freeCapabilities( deviceInfo );
	}

/* Open a session with the device */

static int initFunction( DEVICE_INFO *deviceInfo, const char *name,
						 const int nameLength )
	{
	CRYPTOAPI_INFO *cryptoapiInfo = deviceInfo->deviceCryptoAPI;
	HCRYPTPROV hProv;
	char providerNameBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];
	char keysetNameBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];
	const char *keysetName = NULL;
	DWORD value;
	int i, driverNameLength = nameLength, status;

	/* Check whether a keyset name has been specified */
	for( i = 1; i < nameLength - 1; i++ )
		if( name[ i ] == ':' && name[ i + 1 ] == ':' )
			{
			const int keysetNameLength = nameLength - ( i + 2 );

			if( i > CRYPT_MAX_TEXTSIZE || keysetNameLength <= 0 || \
				keysetNameLength > CRYPT_MAX_TEXTSIZE )
				return( CRYPT_ARGERROR_STR1 );

			/* We've got a keyset name appended to the provider name, break 
			   out the provider and keyset names */
			memcpy( providerNameBuffer, name, i );
			providerNameBuffer[ i ] = '\0';
			memcpy( keysetNameBuffer, name + i + 2, keysetNameLength );
			keysetNameBuffer[ keysetNameLength ] = '\0';
			name = providerNameBuffer;
			keysetName = keysetNameBuffer;
			break;
			}

	/* If we're auto-detecting the device, try various choices */
	if( driverNameLength == 12 && \
		!strnicmp( "[Autodetect]", name, driverNameLength ) )
		{
		if( CryptAcquireContextA( &hProv, keysetName, MS_ENHANCED_PROV, 
								  PROV_RSA_FULL, 0 ) )
			cryptoapiInfo->hProv = hProv;
		else
			if( CryptAcquireContextA( &hProv, keysetName, MS_DEF_PROV, 
									  PROV_RSA_FULL, 0 ) )
				cryptoapiInfo->hProv = hProv;
			else
				return( mapError( cryptoapiInfo, CRYPT_ERROR_NOTFOUND ) );
		}
	else
		{
		/* Try and find a specific provider */
		if( CryptAcquireContextA( &hProv, keysetName, name, PROV_RSA_FULL, 0 ) )
			cryptoapiInfo->hProv = hProv;
		}

	/* Get information on device-specific capabilities */
	value = CRYPT_MAX_TEXTSIZE + 1;
	if( !CryptGetProvParam( cryptoapiInfo->hProv, PP_NAME, 
							cryptoapiInfo->labelBuffer, &value, 0 ) )
		return( mapError( cryptoapiInfo, CRYPT_ERROR_NOTFOUND ) );
	deviceInfo->label = cryptoapiInfo->labelBuffer;
	deviceInfo->flags |= DEVICE_ACTIVE;

	/* Set up the capability information for this device */
	status = getCapabilities( deviceInfo );
	if( cryptStatusError( status ) )
		{
		shutdownFunction( deviceInfo );
		return( ( status == CRYPT_ERROR ) ? CRYPT_ERROR_OPEN : status );
		}

	/* Create the special-purpose key needed to allow symmetric key loads */
	status = createExportKey( cryptoapiInfo->hProv, 
							  &cryptoapiInfo->hPrivateKey, 
							  &cryptoapiInfo->privateKeySize );
	if( cryptStatusError( status ) )
		{
		shutdownFunction( deviceInfo );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_ATTRIBUTE_TYPE type,
							const void *data, const int dataLength )
	{
#if 0
	/* Handle user authorisation */
	if( type == CRYPT_DEVINFO_AUTHENT_USER || \
		type == CRYPT_DEVINFO_AUTHENT_SUPERVISOR )
		{
		/* If the user is already logged in, log them out before we try
		   logging in with a new authentication value */
		if( deviceInfo->flags & DEVICE_LOGGEDIN )
			{
			C_Logout( cryptoapiInfo->hProv );
			deviceInfo->flags &= ~DEVICE_LOGGEDIN;
			}

		/* Authenticate the user to the device */
		status = C_Login( cryptoapiInfo->hProv,
						  ( type == CRYPT_DEVINFO_AUTHENT_USER ) ? \
						  CKU_USER : CKU_SO, ( CK_CHAR_PTR ) data,
						  ( CK_ULONG ) dataLength );
		if( status != CKR_OK && status != CKR_USER_ALREADY_LOGGED_IN )
			return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );

		/* The device is now ready for use */
		deviceInfo->flags |= DEVICE_LOGGEDIN;
		return( CRYPT_OK );
		}

	/* Handle authorisation value change */
#if 0	/* 24/11/02 Removed to see if it's still used by anyone */
	if( type == CRYPT_DEVINFO_SET_AUTHENT_USER || \
		type == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR )
		{
		status = C_SetPIN( cryptoapiInfo->hProv, ( CK_CHAR_PTR ) data2,
						   ( CK_ULONG ) data2Length, ( CK_CHAR_PTR ) data,
						   ( CK_ULONG ) dataLength );
		return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );
		}
#endif /* 0 */

	/* Handle initialisation and zeroisation */
	if( type == CRYPT_DEVINFO_INITIALISE || \
		type == CRYPT_DEVINFO_ZEROISE )
		{
		CK_SESSION_HANDLE hSession;
		CK_CHAR label[ 32 ];

		/* If there's a session active with the device, log out and terminate
		   the session, since the token init will reset this */
		if( cryptoapiInfo->hProv != CRYPT_ERROR )
			{
			C_Logout( cryptoapiInfo->hProv );
			C_CloseSession( cryptoapiInfo->hProv );
			}
		cryptoapiInfo->hProv = CRYPT_ERROR;

		/* Initialise/clear the device */
		memset( label, ' ', 32 );
		status = C_InitToken( deviceInfo->slotHandle, 
							  ( CK_CHAR_PTR ) data,
							  ( CK_ULONG ) dataLength, label );
		if( status != CKR_OK )
			return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );

		/* Reopen the session with the device */
		status = C_OpenSession( deviceInfo->slotHandle,
								CKF_RW_SESSION | CKF_SERIAL_SESSION,
								NULL_PTR, NULL_PTR, &hSession );
		if( status != CKR_OK )
			return( mapError( deviceInfo, status, CRYPT_ERROR_OPEN ) );
		cryptoapiInfo->hProv = hSession;

		/* If it's a straight zeroise, we're done */
		if( type == CRYPT_DEVINFO_ZEROISE )
			return( CRYPT_OK );

		/* We're initialising it, log in as supervisor and set the initial 
		   user PIN to the same as the SSO PIN.  We do this because the init
		   user PIN functionality is a bit of an oddball function that has
		   to fill the gap between C_InitToken() (which sets the SSO PIN) and
		   C_SetPIN() (which can only set the SSO PIN for the SSO or the user 
		   PIN for the user).  Setting the user PIN by the SSO, which is 
		   usually required to perform any useful (non-administrative) 
		   function with the token, requires the special-case C_InitPIN().
		   Since the token will initially be used by the SSO we set it to the 
		   same as the SSO PIN and rely on the SSO to change it before they
		   hand it over to the user.  In most cases the user *is* the SSO, so
		   this ensures that the device behaves as expected when the user 
		   isn't even aware that there are SSO and user roles.  A useful 
		   side-effect of this is that it also eliminates problems with
		   some devices that can behave somewhat strangely if the SSO PIN is 
		   set but the user PIN isn't */
		status = C_Login( cryptoapiInfo->hProv, CKU_SO,
						  ( CK_CHAR_PTR ) data, ( CK_ULONG ) dataLength );
		if( status == CKR_OK )
			status = C_InitPIN( cryptoapiInfo->hProv, 
								( CK_CHAR_PTR ) data, 
								( CK_ULONG ) dataLength );
		if( status != CKR_OK )
			{
			C_Logout( cryptoapiInfo->hProv );
			C_CloseSession( cryptoapiInfo->hProv );
			cryptoapiInfo->hProv = CRYPT_ERROR;
			return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );
			}

		/* We're logged in and ready to go */
		deviceInfo->flags |= DEVICE_LOGGEDIN;
		return( CRYPT_OK );
		}
#endif

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
	CRYPTOAPI_INFO *cryptoapiInfo = deviceInfo->deviceCryptoAPI;

	if( pCryptGenRandom( cryptoapiInfo->hProv, length, buffer ) )
		return( CRYPT_OK );
	return( mapError( cryptoapiInfo, CRYPT_ERROR_FAILED ) );
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

static int getItemFunction( DEVICE_INFO *deviceInfo,
							CRYPT_CONTEXT *iCryptContext,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID, const int keyIDlength,
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	CRYPTOAPI_INFO *cryptoapiInfo = deviceInfo->deviceCryptoAPI;
//	CRYPT_CERTIFICATE iCryptCert;
//	RESOURCE_DATA msgData;
	PCCERT_CONTEXT pCertContext = NULL;
	CRYPT_DATA_BLOB cryptDataBlob;
	CERT_RDN certRDN;
	CERT_RDN_ATTR certRDNAttr;
	CERT_INFO certInfo;
	int status;

	BOOLEAN certViaPrivateKey = FALSE, privateKeyViaCert = FALSE;
	BOOLEAN certPresent = FALSE;
	BOOLEAN cryptAllowed = FALSE, sigAllowed = FALSE;
//	char label[ CRYPT_MAX_TEXTSIZE ];
//	int keySize, actionFlags = 0, labelLength;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );

	/* Set up a search template for the ID type we're using */
	if( keyIDtype == CRYPT_KEYID_NAME )
		{
		memset( &certRDN, 0, sizeof( CERT_RDN ) );
		certRDN.rgRDNAttr = &certRDNAttr;
		certRDN.cRDNAttr = 1;
		memset( &certRDNAttr, 0, sizeof( CERT_RDN_ATTR ) );
		certRDNAttr.pszObjId = szOID_COMMON_NAME;
		certRDNAttr.dwValueType = CERT_RDN_ANY_TYPE;
		certRDNAttr.Value.pbData = ( void * ) keyID;
		certRDNAttr.Value.cbData = keyIDlength;
		}
	if( keyIDtype == CRYPT_KEYID_EMAIL )
		{
		memset( &certRDN, 0, sizeof( CERT_RDN ) );
		certRDN.rgRDNAttr = &certRDNAttr;
		certRDN.cRDNAttr = 1;
		memset( &certRDNAttr, 0, sizeof( CERT_RDN_ATTR ) );
		certRDNAttr.pszObjId = szOID_RSA_emailAddr ;
		certRDNAttr.dwValueType = CERT_RDN_ANY_TYPE;
		certRDNAttr.Value.pbData = ( void * ) keyID;
		certRDNAttr.Value.cbData = keyIDlength;
		}
	if( keyIDtype == CRYPT_IKEYID_CERTID )
		{
		memset( &cryptDataBlob, 0, sizeof( CRYPT_DATA_BLOB ) );
		cryptDataBlob.pbData = ( void * ) keyID;
		cryptDataBlob.cbData = keyIDlength;
		}
	if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
		{
		STREAM stream;
		int length;

		memset( &certInfo, 0, sizeof( CERT_INFO ) );
		sMemConnect( &stream, keyID, keyIDlength );
		readSequence( &stream, NULL );
		certInfo.Issuer.pbData = sMemBufPtr( &stream );
		readSequence( &stream, &length );		/* Issuer DN */
		certInfo.Issuer.cbData = ( int ) sizeofObject( length );
		sSkip( &stream, length );
		certInfo.SerialNumber.pbData = sMemBufPtr( &stream );
		readGenericHole( &stream, &length, BER_INTEGER );/* Serial number */
		certInfo.SerialNumber.cbData = ( int ) sizeofObject( length );
		assert( sStatusOK( &stream ) );
		sMemDisconnect( &stream );
		}

	/* Try for a cert first */
	switch( keyIDtype )
		{
		case CRYPT_KEYID_NAME:
			pCertContext = \
				pCertFindCertificateInStore( hCertStore,
							X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_ATTR,
							&certRDN, NULL );
			break;

		case CRYPT_KEYID_EMAIL:
			/* There doesn't appear to be any way to locate a cert using the 
			   email address in an altName, so we have to restrict ourselves 
			   to the most commonly-used OID for certs in DNs */
			pCertContext = \
				pCertFindCertificateInStore( hCertStore,
							X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_ATTR,
							&certRDN, NULL );
			break;

		case CRYPT_IKEYID_KEYID:
			/* There doesn't appear to be any way to locate a cert using a 
			   subjectKeyIdentifier */
			break;

		case CRYPT_IKEYID_CERTID:
			pCertContext = \
				pCertFindCertificateInStore( hCertStore,
							X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH,
							&cryptDataBlob, NULL );
			break;

		case CRYPT_IKEYID_ISSUERANDSERIALNUMBER:
			pCertContext = \
				pCertGetSubjectCertificateFromStore( hCertStore,
							X509_ASN_ENCODING, &certInfo );
			break;

		default:
			assert( NOTREACHED );
		}
	if( pCertContext != NULL )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* If we're just checking whether an object exists, return now.  If 
		   all we want is the key label, copy it back to the caller and 
		   exit */
		if( flags & KEYMGMT_FLAG_CHECK_ONLY )
			{
			pCertFreeCertificateContext( pCertContext );
			return( CRYPT_OK );
			}
		if( flags & KEYMGMT_FLAG_LABEL_ONLY )
			{
//			status = getObjectLabel( deviceInfo, iCryptCert, 
//									 auxInfo, auxInfoLength );
status = CRYPT_ERROR;
			pCertFreeCertificateContext( pCertContext );
			return( status );
			}

		/* Import the cert as a cryptlib object */
		setMessageCreateObjectIndirectInfo( &createInfo, 
									pCertContext->pbCertEncoded, 
									pCertContext->cbCertEncoded,
									CRYPT_CERTTYPE_CERTIFICATE );
		createInfo.arg1 = CRYPT_CERTTYPE_CERTIFICATE;
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusOK( status ) )
			*iCryptContext = createInfo.cryptHandle;
	
		/* If there was a problem or we're only looking for a public key,
		   we're done */
		if( cryptStatusError( status ) || \
			itemType == KEYMGMT_ITEM_PUBLICKEY )
			{
			pCertFreeCertificateContext( pCertContext );
			return( status );
			}
		}
	else
		/* If we're looking for a specific match on a certificate (rather 
		   than just a general public key) and we don't find anything, 
		   exit now */
		if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
			return( mapError( cryptoapiInfo, CRYPT_ERROR_NOTFOUND ) );

	/* There were no certs found.  At this point we can approach the problem 
	   from one of two sides, if we've got a certHash or an 
	   issuerAndSerialNumber we have to find the matching cert and get the 
	   key from that, otherwise we find the key and get the cert from that */
	if( keyIDtype == CRYPT_IKEYID_CERTID || \
		keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
		{
//		status = findObjectFromObject( deviceInfo, hCertificate, 
//									   CKO_PRIVATE_KEY, &hObject );
		if( cryptStatusError( status ) )
			return( status );
	
		/* Remember that we've got a cert to attach to the private key */
		privateKeyViaCert = TRUE;
		}
#if 0
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
		cryptStatus = findObject( deviceInfo, &hObject, keyTemplate, 
								  keyTemplateCount );
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
			cryptStatus = findObject( deviceInfo, &hObject, keyTemplate, 
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

		cryptStatus = findObject( deviceInfo, &hObject, 
								  decryptKeyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			{
			decryptKeyTemplate[ 1 ].type = CKA_UNWRAP;
			cryptStatus = findObject( deviceInfo, &hObject, 
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
		return( getObjectLabel( deviceInfo, hObject, auxInfo, 
								auxInfoLength ) );

	/* We found something, map the key type to a cryptlib algorithm ID,
	   determine the key size, and find its capabilities */
	keyTypeTemplate.pValue = &keyType;
	C_GetAttributeValue( cryptoapiInfo->hProv, hObject, 
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
	C_GetAttributeValue( cryptoapiInfo->hProv, hObject, 
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
		cryptStatus = instantiateCert( deviceInfo, hCertificate, 
									   &iCryptCert, FALSE );
		if( cryptStatusError( cryptStatus ) )
			return( cryptStatus );
		certPresent = TRUE;
		}
	else
		{
		cryptStatus = findCertFromObject( deviceInfo, hObject, &iCryptCert, 
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
	if( readFlag( deviceInfo, hObject, CKA_ENCRYPT ) || \
		readFlag( deviceInfo, hObject, CKA_UNWRAP ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL );
		cryptAllowed = TRUE;
		}
	if( readFlag( deviceInfo, hObject, CKA_DECRYPT ) || \
		readFlag( deviceInfo, hObject, CKA_UNWRAP ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
		cryptAllowed = TRUE;
		}
	if( readFlag( deviceInfo, hObject, CKA_SIGN ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
		sigAllowed = TRUE;
		}
	if( readFlag( deviceInfo, hObject, CKA_VERIFY ) )
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
	cryptStatus = getObjectLabel( deviceInfo, hObject, label, &labelLength );
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
		cryptStatus = rsaSetPublicComponents( deviceInfo, *iCryptContext, 
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
#endif

	return( CRYPT_ERROR );
	}

/* Update a device with a certificate */

static int setItemFunction( DEVICE_INFO *deviceInfo, 
							const CRYPT_HANDLE iCryptHandle )
	{
	CRYPT_CERTIFICATE iCryptCert;
	int status;

	/* Lock the cert for our exclusive use (in case it's a cert chain, we 
	   also select the first cert in the chain), update the device with the 
	   cert, and unlock it to allow others access */
	krnlSendMessage( iCryptHandle, IMESSAGE_GETDEPENDENT, &iCryptCert, 
					 OBJECT_TYPE_CERTIFICATE );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORFIRST, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
#if 0
	status = updateCertificate( deviceInfo, iCryptCert );
#endif
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_FALSE, 
					 CRYPT_IATTRIBUTE_LOCKED );

	return( status );
	}

/* Delete an object in a device */

static int deleteItemFunction( DEVICE_INFO *deviceInfo,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
#if 0
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
	cryptStatus = findObjectEx( deviceInfo, &hCertificate, certTemplate, 3 );
	if( cryptStatusOK( cryptStatus ) )
		{
		/* We got a cert, if there are associated keys delete them as well */
		cryptStatus = findObjectFromObject( deviceInfo, hCertificate, 
											CKO_PUBLIC_KEY, &hPubkey );
		if( cryptStatusError( cryptStatus ) )
			hPubkey = CRYPT_ERROR;
		cryptStatus = findObjectFromObject( deviceInfo, hCertificate, 
											CKO_PRIVATE_KEY, &hPrivkey );
		if( cryptStatusError( cryptStatus ) )
			hPrivkey = CRYPT_ERROR;
		}
	else
		{
		/* We didn't find a cert with the given label, try for public and
		   private keys */
		cryptStatus = findObjectEx( deviceInfo, &hPubkey, keyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			hPubkey = CRYPT_ERROR;
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &privkeyClass;
		cryptStatus = findObjectEx( deviceInfo, &hPrivkey, keyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			hPrivkey = CRYPT_ERROR;

		/* There may be an unlabelled cert present, try and find it by 
		   looking for a cert matching the key ID */
		if( hPubkey != CRYPT_ERROR || hPrivkey != CRYPT_ERROR )
			{
			cryptStatus = findObjectFromObject( deviceInfo, 
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
		cryptStatus = findObjectFromObject( deviceInfo, hPubkey, 
											CKO_PRIVATE_KEY, &hPrivkey );
		if( cryptStatusError( cryptStatus ) )
			hPrivkey = CRYPT_ERROR;
		}
	if( hPrivkey != CRYPT_ERROR && hPubkey == CRYPT_ERROR )
		{
		cryptStatus = findObjectFromObject( deviceInfo, hPrivkey, 
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
		status = C_DestroyObject( cryptoapiInfo->hProv, hCertificate );
	if( hPubkey != CRYPT_ERROR )
		{
		int status2;

		status2 = C_DestroyObject( cryptoapiInfo->hProv, hPubkey );
		if( status2 != CKR_OK && status == CKR_OK )
			status = status2;
		}
	if( hPrivkey != CRYPT_ERROR )
		{
		int status2;

		status2 = C_DestroyObject( cryptoapiInfo->hProv, hPrivkey );
		if( status2 != CKR_OK && status == CKR_OK )
			status = status2;
		}
	if( status != CKR_OK )
		cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	return( cryptStatus );
#endif

	return( CRYPT_ERROR );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

#if 0

/* Sign data, check a signature.  We use Sign and Verify rather than the
   xxxRecover variants because there's no need to use Recover, and because
   many implementations don't do Recover */

static int genericSign( DEVICE_INFO *deviceInfo, CONTEXT_INFO *contextInfoPtr,
						const CK_MECHANISM *pMechanism, 
						const void *inBuffer, const int inLength, 
						void *outBuffer, const int outLength )
	{
	CK_ULONG resultLen = outLength;
	CK_RV status;

	status = C_SignInit( cryptoapiInfo->hProv,
						 ( CK_MECHANISM_PTR ) pMechanism, 
						 contextInfoPtr->deviceObject );
	if( status == CKR_OK )
		status = C_Sign( cryptoapiInfo->hProv, ( CK_BYTE_PTR ) inBuffer, 
						 inLength, outBuffer, &resultLen );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );

	return( CRYPT_OK );
	}

static int genericVerify( DEVICE_INFO *deviceInfo, CONTEXT_INFO *contextInfoPtr,
						  const CK_MECHANISM *pMechanism, 
						  const void *inBuffer, const int inLength, 
						  void *outBuffer, const int outLength )
	{
	CK_RV status;

	status = C_VerifyInit( cryptoapiInfo->hProv,
						   ( CK_MECHANISM_PTR ) pMechanism,
						   contextInfoPtr->deviceObject );
	if( status == CKR_OK )
		status = C_Verify( cryptoapiInfo->hProv, ( CK_BYTE_PTR ) inBuffer, 
						   inLength, outBuffer, outLength );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );

	return( CRYPT_OK );
	}
#endif /* 0 */

/* Encrypt, decrypt.  We always set the bFinal flag to FALSE since setting it
   to TRUE tries to apply message padding, resets the IV, and various other
   unwanted side-effects */

static int genericEncrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						   const int length, const int outLength )
	{
	int resultLength = length;

	if( !pCryptEncrypt( contextInfoPtr->deviceObject, 0, FALSE, 0, buffer, 
						&resultLength, outLength ) )
		return( mapDeviceError( contextInfoPtr, CRYPT_ERROR_FAILED ) );
	return( CRYPT_OK );
	}

static int genericDecrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						   const int length, int *resultLength )
	{
	*resultLength = length;
	if( !pCryptDecrypt( contextInfoPtr->deviceObject, 0, FALSE, 0, buffer, 
						resultLength ) )
		return( mapDeviceError( contextInfoPtr, CRYPT_ERROR_FAILED ) );

	return( CRYPT_OK );
	}

/* Clean up the object associated with a context */

static int genericEndFunction( CONTEXT_INFO *contextInfoPtr )
	{
	/* Destroy the object */
	if( contextInfoPtr->capabilityInfo->keySize > 0 )
		pCryptDestroyKey( contextInfoPtr->deviceObject );
	else
		pCryptDestroyHash( contextInfoPtr->deviceObject );
	return( CRYPT_OK );
	}

#if 0

/* RSA algorithm-specific mapping functions.  Externally we always appear to 
   use the X.509 (raw) mechanism for the encrypt/decrypt/sign/verify 
   functions since cryptlib does its own padding (with workarounds for 
   various bugs and peculiarities).  Internally however we have to use the
   PKCS mechanism since some implementations don't support the X.509
   mechanism, and add/remove the padding to fake out the presence of a raw
   RSA mechanism */

static int rsaSetPublicComponents( DEVICE_INFO *deviceInfo, 
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
	status = C_GetAttributeValue( cryptoapiInfo->hProv, hRsaKey, 
								  &nTemplate, 1 );
	if( status == CKR_OK )
		{
		nTemplate.pValue = n;
		status = C_GetAttributeValue( cryptoapiInfo->hProv, hRsaKey, 
									  &nTemplate, 1 );
		}
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	status = C_GetAttributeValue( cryptoapiInfo->hProv, hRsaKey, 
								  &eTemplate, 1 );
	if( status == CKR_OK )
		{
		eTemplate.pValue = e;
		status = C_GetAttributeValue( cryptoapiInfo->hProv, hRsaKey, 
									  &eTemplate, 1 );
		}
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
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

static int rsaSetKeyInfo( DEVICE_INFO *deviceInfo, CONTEXT_INFO *contextInfoPtr, 
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
			C_SetAttributeValue( cryptoapiInfo->hProv, hPublicKey, 
								 &idTemplate, 1 );
		C_SetAttributeValue( cryptoapiInfo->hProv, hPrivateKey, 
							 &idTemplate, 1 );
		}
	
	return( cryptStatus );
	}
#endif /* 0 */

static int rsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					   const int keyLength )
	{
#if 0
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
	status = C_CreateObject( cryptoapiInfo->hProv, rsaKeyTemplate, 
							 templateCount, &hRsaKey );
	zeroise( rsaKeyTemplate, sizeof( CK_ATTRIBUTE ) * templateCount );
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
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
	cryptStatus = rsaSetPublicComponents( deviceInfo, 
										  contextInfoPtr->objectHandle, hRsaKey );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = rsaSetKeyInfo( deviceInfo, contextInfoPtr, 
									 hRsaKey, CRYPT_UNUSED );
	if( cryptStatusError( cryptStatus ) )
		C_DestroyObject( cryptoapiInfo->hProv, hRsaKey );

	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
#endif /* 0 */
	return( CRYPT_ERROR );
	}

static int rsaGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keysizeBits )
	{
#if 0
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
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Patch in the key size and generate the keys */
	publicKeyTemplate[ 5 ].pValue = ( CK_VOID_PTR ) &modulusBits;
	status = C_GenerateKeyPair( cryptoapiInfo->hProv,
								( CK_MECHANISM_PTR ) &mechanism,
								publicKeyTemplate, 6, privateKeyTemplate, 6,
								&hPublicKey, &hPrivateKey );
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		{
		krnlReleaseObject( deviceInfo->objectHandle );
		return( cryptStatus );
		}

	/* Send the keying info to the context and set up the key ID info */
	cryptStatus = rsaSetPublicComponents( deviceInfo, 
										  contextInfoPtr->objectHandle, hPublicKey );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = rsaSetKeyInfo( deviceInfo, contextInfoPtr, hPrivateKey, 
									 hPublicKey );
	if( cryptStatusError( cryptStatus ) )
		{
		C_DestroyObject( cryptoapiInfo->hProv, hPublicKey );
		C_DestroyObject( cryptoapiInfo->hProv, hPrivateKey );
		}

	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
#endif /* 0 */
	return( CRYPT_ERROR );
	}

static int rsaSign( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
#if 0
	static const CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE *bufPtr = buffer;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC.keySizeBits );
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
	cryptStatus = genericSign( deviceInfo, contextInfoPtr, &mechanism, bufPtr + i, 
							   keySize - i, buffer, keySize );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
#endif /* 0 */
	return( CRYPT_ERROR );
	}

static int rsaVerify( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
#if 0
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE data[ CRYPT_MAX_PKCSIZE ];
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC.keySizeBits );
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
	cryptStatus = genericVerify( deviceInfo, contextInfoPtr, &mechanism, data,
								 keySize, buffer, keySize );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
#endif /* 0 */
	return( CRYPT_ERROR );
	}

static int rsaEncrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
#if 0
	static const CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE *bufPtr = buffer;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC.keySizeBits );
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
	cryptStatus = genericEncrypt( deviceInfo, contextInfoPtr, &mechanism, bufPtr,
								  keySize - i, keySize );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
#endif /* 0 */
	return( CRYPT_ERROR );
	}

static int rsaDecrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
#if 0
	static const CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE *bufPtr = buffer;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC.keySizeBits );
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
	cryptStatus = genericDecrypt( deviceInfo, contextInfoPtr, &mechanism, buffer,
								  keySize, &resultLen );
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
#endif /* 0 */
	return( CRYPT_ERROR );
	}

/* DSA algorithm-specific mapping functions */

static int dsaSetKeyInfo( DEVICE_INFO *deviceInfo, CONTEXT_INFO *contextInfoPtr, 
//						  const CK_OBJECT_HANDLE hPrivateKey,
//						  const CK_OBJECT_HANDLE hPublicKey,
						  const void *p, const int pLen,
						  const void *q, const int qLen,
						  const void *g, const int gLen,
						  const void *y, const int yLen )
	{
#if 0
	RESOURCE_DATA msgData;
	BYTE keyDataBuffer[ CRYPT_MAX_PKCSIZE * 2 ], idBuffer[ KEYID_SIZE ];
	int keyDataSize, cryptStatus;

	/* Send the public key data to the context.  We send the keying info as
	   CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL rather than CRYPT_IATTRIBUTE_KEY_SPKI
	   since the latter transitions the context into the high state.  We 
	   don't want to do this because we're already in the middle of processing
	   a message that does this on completion, all we're doing here is 
	   sending in encoded public key data for use by objects such as 
	   certificates */
	cryptStatus = keyDataSize = writeFlatPublicKey( NULL, 0, CRYPT_ALGO_DSA, 
													p, pLen, q, qLen, 
													g, gLen, y, yLen );
	if( !cryptStatusError( cryptStatus ) )
		cryptStatus = writeFlatPublicKey( keyDataBuffer, CRYPT_MAX_PKCSIZE * 2,
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
			C_SetAttributeValue( cryptoapiInfo->hProv, hPublicKey, 
								 &idTemplate, 1 );
		C_SetAttributeValue( cryptoapiInfo->hProv, hPrivateKey, 
							 &idTemplate, 1 );
		}
	
	return( cryptStatus );
#endif /* 0 */
	return( CRYPT_ERROR );
	}

static int dsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					   const int keyLength )
	{
#if 0
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
		readGenericHole( &stream, &yValueLength );	/* INTEGER */
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
	status = C_CreateObject( cryptoapiInfo->hProv, dsaKeyTemplate, 
							 templateCount, &hDsaKey );
	zeroise( dsaKeyTemplate, sizeof( CK_ATTRIBUTE ) * templateCount );
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
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
	cryptStatus = dsaSetKeyInfo( deviceInfo, contextInfoPtr, 
								 hDsaKey, CRYPT_UNUSED,
								 dsaKey->p, bitsToBytes( dsaKey->pLen ), 
								 dsaKey->q, bitsToBytes( dsaKey->qLen ),
								 dsaKey->g, bitsToBytes( dsaKey->gLen ),
								 ( dsaKey->isPublicKey ) ? dsaKey->y : yValue,
								 ( dsaKey->isPublicKey ) ? \
									bitsToBytes( dsaKey->yLen ) : yValueLength );
	if( cryptStatusError( cryptStatus ) )
		C_DestroyObject( cryptoapiInfo->hProv, hDsaKey );

	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
#endif /* 0 */
	return( CRYPT_ERROR );
	}

static int dsaGenerateKey( CONTEXT_INFO *contextInfoPtr, const int keysizeBits )
	{
#if 0
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
	readGenericHole( &stream, &length );					/* p */
	publicKeyTemplate[ 3 ].pValue = sMemBufPtr( &stream );
	publicKeyTemplate[ 3 ].ulValueLen = length;
	sSkip( &stream, length );
	readGenericHole( &stream, &length );					/* q */
	publicKeyTemplate[ 4 ].pValue = sMemBufPtr( &stream );
	publicKeyTemplate[ 4 ].ulValueLen = length;
	sSkip( &stream, length );
	readGenericHole( &stream, &length );					/* g */
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
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Generate the keys */
	status = C_GenerateKeyPair( cryptoapiInfo->hProv,
								( CK_MECHANISM_PTR ) &mechanism,
								( CK_ATTRIBUTE_PTR ) publicKeyTemplate, 5,
								( CK_ATTRIBUTE_PTR ) privateKeyTemplate, 4,
								&hPublicKey, &hPrivateKey );
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		{
		krnlReleaseObject( deviceInfo->objectHandle );
		return( cryptStatus );
		}

	/* Read back the generated y value, send the public key info to the 
	   context, and set up the key ID info.  The odd two-phase y value read 
	   is necessary for buggy implementations that fail if the given size 
	   isn't exactly the same as the data size */
	status = C_GetAttributeValue( cryptoapiInfo->hProv, hPublicKey,
								  &yValueTemplate, 1 );
	if( status == CKR_OK )
		{
		yValueTemplate.pValue = pubkeyBuffer;
		status = C_GetAttributeValue( cryptoapiInfo->hProv, hPublicKey, 
									  &yValueTemplate, 1 );
		}
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = dsaSetKeyInfo( deviceInfo, contextInfoPtr, 
			hPrivateKey, hPublicKey,
			publicKeyTemplate[ 3 ].pValue, publicKeyTemplate[ 3 ].ulValueLen, 
			publicKeyTemplate[ 4 ].pValue, publicKeyTemplate[ 4 ].ulValueLen, 
			publicKeyTemplate[ 5 ].pValue, publicKeyTemplate[ 5 ].ulValueLen,
			yValueTemplate.pValue, yValueTemplate.ulValueLen );
	if( cryptStatusError( cryptStatus ) )
		{
		C_DestroyObject( cryptoapiInfo->hProv, hPublicKey );
		C_DestroyObject( cryptoapiInfo->hProv, hPrivateKey );
		}

	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
#endif /* 0 */
	return( CRYPT_ERROR );
	}

static int dsaSign( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
#if 0
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
	cryptStatus = genericSign( deviceInfo, contextInfoPtr, &mechanism, 
							   dlpParams->inParam1, dlpParams->inLen1,
							   signature, 40 );
	krnlReleaseObject( deviceInfo->objectHandle );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* Encode the result as a DL data block.  We have to do this as via 
	   bignums, but this isn't a big deal since DSA signing via tokens is
	   almost never used */
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
#endif /* 0 */
	return( CRYPT_ERROR );
	}

static int dsaVerify( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
#if 0
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
	cryptStatus = genericVerify( deviceInfo, contextInfoPtr, &mechanism, buffer,
								 20, signature, 40 );
	krnlReleaseObject( deviceInfo->objectHandle );
	return( cryptStatus );
#endif /* 0 */
	return( CRYPT_ERROR );
	}

/* Conventional cipher-specific mapping functions */

static int cipherInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
						  const int keyLength )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	CRYPTOAPI_INFO *cryptoapiInfo;
	HCRYPTKEY hSessionKey;
	int keySize = keyLength, status;

	/* Get the info for the device associated with this context */
	status = krnlSendMessage( contextInfoPtr->objectHandle, IMESSAGE_GETDEPENDENT, 
							  &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( status ) )
		status = krnlGetObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( void ** ) &deviceInfo, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	cryptoapiInfo = deviceInfo->deviceCryptoAPI;
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

	/* Import the key via the hideous decrypt-with-exponent-one RSA key 
	   kludge */
	importPlainKey( cryptoapiInfo->hProv, cryptoapiInfo->hPrivateKey, 
					cryptoapiInfo->privateKeySize, &hSessionKey, 
					contextInfoPtr->capabilityInfo->cryptAlgo, key, 
					keySize );
	if( cryptStatusOK( status ) )
		contextInfoPtr->deviceObject = hSessionKey;

	krnlReleaseObject( deviceInfo->objectHandle );
	return( status );
	}

/* Set up algorithm-specific encryption parameters */

int initKeyParamsFunction( CONTEXT_INFO *contextInfoPtr, const void *iv, 
						   const int ivLength, const CRYPT_MODE_TYPE mode )
	{
	int status;

	assert( ( iv != NULL && ( ivLength == CRYPT_USE_DEFAULT || ivLength > 0 ) ) || \
			( mode != CRYPT_UNUSED ) );

	/* Set the en/decryption mode if required */
	if( mode != CRYPT_UNUSED )
		{
		enum { CAPI_CRYPT_MODE_NONE, CAPI_CRYPT_MODE_CBC, 
			   CAPI_CRYPT_MODE_ECB, CAPI_CRYPT_MODE_OFB,
			   CAPI_CRYPT_MODE_CFB };
		DWORD dwMode;

		/* Reflect the new mode down to the context */
		status = initKeyParams( contextInfoPtr, NULL, 0, mode );
		if( cryptStatusError( status ) )
			return( status );

		/* Make sure that the values from the CryptoAPI header aren't 
		   overriding the cryptlib values */
		assert( CRYPT_MODE_ECB == 1 );
		assert( CRYPT_MODE_CBC == 2 );
		assert( CRYPT_MODE_CFB == 3 );
		assert( CRYPT_MODE_OFB == 4 );

		/* CryptoAPI uses the same mode names as cryptlib but different 
		   values, so we have to override the naming with our own names
		   here and then map the cryptlib values to the CryptoAPI ones */
		switch( mode )
			{
			case CRYPT_MODE_ECB:
				dwMode = CAPI_CRYPT_MODE_ECB;
				break;
			case CRYPT_MODE_CBC:
				dwMode = CAPI_CRYPT_MODE_CBC;
				break;
			case CRYPT_MODE_CFB:
				dwMode = CAPI_CRYPT_MODE_CFB;
				break;
			case CRYPT_MODE_OFB:
				dwMode = CAPI_CRYPT_MODE_OFB;
				break;
			default:
				assert( NOTREACHED );
			}
		
		/* Set the parameters for the CryptoAPI object */
		if( !CryptSetKeyParam( contextInfoPtr->deviceObject, KP_MODE,
							   ( BYTE * ) &dwMode, 0 ) )
			return( mapDeviceError( contextInfoPtr, CRYPT_ERROR_NOTAVAIL ) );
		if( mode == CRYPT_MODE_CFB || mode == CRYPT_MODE_OFB )
			{
			const DWORD dwModeBits = contextInfoPtr->capabilityInfo->blockSize * 8;

			/* CryptoAPI defaults to 8-bit feedback for CFB and OFB (!!) so 
			   we have to fix the feedback amount if we're using a stream 
			   mode */
			if( !CryptSetKeyParam( contextInfoPtr->deviceObject, KP_MODE_BITS,
								   ( BYTE * ) &dwModeBits, 0 ) )
				return( mapDeviceError( contextInfoPtr, CRYPT_ERROR_NOTAVAIL ) );
			}
		}

	/* If there's no IV present, we're done */
	if( iv == NULL )
		return( CRYPT_OK );

	/* Reflect the IV down to the context */
	status = initKeyParams( contextInfoPtr, iv, ivLength, mode );
	if( cryptStatusError( status ) )
		return( status );

	/* Set the parameters for the CryptoAPI object */
	if( !CryptSetKeyParam( contextInfoPtr->deviceObject, KP_IV,
						   contextInfoPtr->ctxConv->currentIV, 0 ) )
		return( mapDeviceError( contextInfoPtr, CRYPT_ERROR_FAILED ) );

	return( CRYPT_OK );
	}

/* En/decrypt/hash data */

static int cipherEncrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
	return( genericEncrypt( contextInfoPtr, buffer, length, length ) );
	}
static int cipherDecrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
	return( genericEncrypt( contextInfoPtr, buffer, length, length ) );
	}
static int hashFunction( CONTEXT_INFO *contextInfoPtr, void *buffer, int length )
	{
	if( !pCryptHashData( contextInfoPtr->deviceObject, buffer, length, 0 ) )
		return( mapDeviceError( contextInfoPtr, CRYPT_ERROR_FAILED ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Capability Routines						*
*																			*
****************************************************************************/

/* Since cryptlib's CAPABILITY_INFO is fixed, all of the fields are declared
   const so that they'll (hopefully) be allocated in the code segment.  This 
   doesn't quite work for CryptoAPI providers since things like the available 
   key lengths can vary depending on the providers, so we declare an 
   equivalent structure here that makes the variable fields non-const.  Once 
   the fields are set up, the result is copied into a dynamically-allocated 
   CAPABILITY_INFO block at which point the fields are treated as const by 
   the code */

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
	{ CRYPT_ALGO_MD4, bits( 128 ), "MD4",
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_MD5, bits( 128 ), "MD5",
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_SHA, bits( 160 ), "SHA",
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_RIPEMD160, bits( 160 ), "RIPEMD-160",
		bits( 0 ), bits( 0 ), bits( 0 ) },

	/* Public-key capabilities */
	{ CRYPT_ALGO_RSA, bits( 0 ), "RSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE },
	{ CRYPT_ALGO_DSA, bits( 0 ), "DSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE },

	/* Hier ist der Mast zu ende */
	{ CRYPT_ERROR }
	};

/* Mapping of CryptoAPI provider capabilities to cryptlib capabilities */

typedef struct {
	/* Mapping information from CryptoAPI to cryptlib algorithms.  For some
	   PKC algorithms CryptoAPI creates two virtual algorithm types (badly,
	   it's easily confused between the two), one for signing and one for 
	   encryption.  The first algorithm type is always the one with 
	   encryption capability, if there's one with signature capability or 
	   it's a siganture-only algorithm we specify it as the optional 
	   alternative algorithm type */
	const ALG_ID algoID;				/* CryptoAPI algorithm type */
	const ALG_ID altAlgoID;				/* CryptoAPI alt.algorithm type */
	const CRYPT_ALGO_TYPE cryptAlgo;	/* cryptlib algo and mode */
	const CRYPT_MODE_TYPE cryptMode;

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
	{ CALG_RSA_KEYX, CALG_RSA_SIGN, CRYPT_ALGO_RSA, CRYPT_MODE_NONE, 
	  NULL, rsaInitKey, rsaGenerateKey, 
	  rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify },
	{ CRYPT_ERROR, CALG_DSS_SIGN, CRYPT_ALGO_DSA, CRYPT_MODE_NONE, 
	  NULL, dsaInitKey, dsaGenerateKey, 
	  NULL, NULL, dsaSign, dsaVerify },
	{ CALG_DES, CRYPT_ERROR, CRYPT_ALGO_DES, CRYPT_MODE_ECB, 
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CALG_3DES, CRYPT_ERROR, CRYPT_ALGO_3DES, CRYPT_MODE_ECB, 
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CALG_RC2, CRYPT_ERROR, CRYPT_ALGO_RC2, CRYPT_MODE_ECB, 
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CALG_RC4, CRYPT_ERROR, CRYPT_ALGO_RC4, CRYPT_MODE_OFB, 
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CALG_SKIPJACK, CRYPT_ERROR, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_ECB,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CALG_MD2, CRYPT_ERROR, CRYPT_ALGO_MD2, CRYPT_MODE_NONE,
	  genericEndFunction, NULL, NULL, 
	  hashFunction, hashFunction, NULL, NULL },
	{ CALG_MD4, CRYPT_ERROR, CRYPT_ALGO_MD4, CRYPT_MODE_NONE,
	  genericEndFunction, NULL, NULL, 
	  hashFunction, hashFunction, NULL, NULL },
	{ CALG_MD5, CRYPT_ERROR, CRYPT_ALGO_MD5, CRYPT_MODE_NONE,
	  genericEndFunction, NULL, NULL, 
	  hashFunction, hashFunction, NULL, NULL },
	{ CALG_SHA1, CRYPT_ERROR, CRYPT_ALGO_SHA, CRYPT_MODE_NONE,
	  genericEndFunction, NULL, NULL, 
	  hashFunction, hashFunction, NULL, NULL },
	{ CRYPT_ERROR, CRYPT_ERROR, CRYPT_ALGO_NONE, CRYPT_MODE_NONE }
	};

/* Fill out a capability info based on CryptoAPI algorithm info */

static CAPABILITY_INFO *addCapability( const DEVICE_INFO *deviceInfo,
									   const PROV_ENUMALGS_EX *capiAlgoInfo,
									   const MECHANISM_INFO *mechanismInfoPtr,
									   const CAPABILITY_INFO *existingCapabilityInfo )
	{
	VARIABLE_CAPABILITY_INFO *capabilityInfo = \
					( VARIABLE_CAPABILITY_INFO * ) existingCapabilityInfo;
	const CRYPT_ALGO_TYPE cryptAlgo = mechanismInfoPtr->cryptAlgo;
	int minKeySize, maxKeySize, i;

	/* If it's a new capability, copy across the template for this 
	   capability */
	if( capabilityInfo == NULL )
		{
		if( ( capabilityInfo = \
				clAlloc( "addCapability", sizeof( CAPABILITY_INFO ) ) ) == NULL )
			return( NULL );
		for( i = 0; \
			 capabilityTemplates[ i ].cryptAlgo != mechanismInfoPtr->cryptAlgo && \
			 capabilityTemplates[ i ].cryptAlgo != CRYPT_ERROR; \
			 i++ );
		assert( i < sizeof( capabilityTemplates ) / sizeof( CAPABILITY_INFO ) && \
				capabilityTemplates[ i ].cryptAlgo != CRYPT_ERROR );
		memcpy( capabilityInfo, &capabilityTemplates[ i ],
				sizeof( CAPABILITY_INFO ) );
		}

	/* Set up the keysize information, limiting the maximum key size to 
	   match the cryptlib native max.key size, both for consistency and 
	   because cryptlib performs buffer allocation based on the maximum 
	   native buffer size.  Since CryptoAPI specifies key sizes for unkeyed 
	   hash algorithms, we only set the keysize if there's really a key
	   present.  In addition it indicates the number of bits involved in 
	   keying rather than the nominal key size, so we have to adjust the
	   reported size to match the conventionally-used value */
	if( capabilityInfo->keySize > 0 )
		{
		minKeySize = bitsToBytes( capiAlgoInfo->dwMinLen );
		maxKeySize = bitsToBytes( capiAlgoInfo->dwMaxLen );
		if( mechanismInfoPtr->cryptAlgo == CRYPT_ALGO_DES && \
			minKeySize == 7 )
			/* Adjust 56 bits -> 8 bytes */
			minKeySize = maxKeySize = 8;
		if( mechanismInfoPtr->cryptAlgo == CRYPT_ALGO_3DES && \
			minKeySize == 21 )
			/* Adjust 168 bits -> 24 bytes */
			minKeySize = maxKeySize = 24;
		if( minKeySize > capabilityInfo->minKeySize )
			capabilityInfo->minKeySize = minKeySize;
		if( capabilityInfo->keySize < capabilityInfo->minKeySize )
			capabilityInfo->keySize = capabilityInfo->minKeySize;
		capabilityInfo->maxKeySize = min( maxKeySize, 
										  capabilityInfo->maxKeySize );
		if( capabilityInfo->keySize > capabilityInfo->maxKeySize )
			capabilityInfo->keySize = capabilityInfo->maxKeySize;
		capabilityInfo->endFunction = genericEndFunction;
		}

	/* Set up the device-specific handlers */
	capabilityInfo->getInfoFunction = getInfo;
	if( mechanismInfoPtr->cryptAlgo != CRYPT_ALGO_RSA && \
		mechanismInfoPtr->cryptAlgo != CRYPT_ALGO_DSA )
		capabilityInfo->initKeyParamsFunction = initKeyParamsFunction;
	capabilityInfo->endFunction = mechanismInfoPtr->endFunction;
	capabilityInfo->initKeyFunction = mechanismInfoPtr->initKeyFunction;
	capabilityInfo->generateKeyFunction = mechanismInfoPtr->generateKeyFunction;
	if( mechanismInfoPtr->algoID == capiAlgoInfo->aiAlgid )
		{
		if( mechanismInfoPtr->cryptMode == CRYPT_MODE_OFB )
			/* Stream ciphers have an implicit mode of OFB */
			capabilityInfo->encryptOFBFunction = mechanismInfoPtr->encryptFunction;
		else
			capabilityInfo->encryptFunction = mechanismInfoPtr->encryptFunction;
		if( mechanismInfoPtr->cryptMode == CRYPT_MODE_OFB )
			/* Stream ciphers have an implicit mode of OFB */
			capabilityInfo->decryptOFBFunction = mechanismInfoPtr->decryptFunction;
		else
			capabilityInfo->decryptFunction = mechanismInfoPtr->decryptFunction;
		if( mechanismInfoPtr->cryptMode != CRYPT_MODE_NONE && \
			mechanismInfoPtr->cryptMode != CRYPT_MODE_OFB )
			{
			capabilityInfo->encryptCBCFunction = \
										mechanismInfoPtr->encryptFunction;
			capabilityInfo->decryptCBCFunction = \
										mechanismInfoPtr->decryptFunction;
			capabilityInfo->encryptCFBFunction = \
										mechanismInfoPtr->encryptFunction;
			capabilityInfo->decryptCFBFunction = \
										mechanismInfoPtr->decryptFunction;
			capabilityInfo->encryptOFBFunction = \
										mechanismInfoPtr->encryptFunction;
			capabilityInfo->decryptOFBFunction = \
										mechanismInfoPtr->decryptFunction;
			}
		}
	if( mechanismInfoPtr->altAlgoID == capiAlgoInfo->aiAlgid )
		{
		capabilityInfo->signFunction = mechanismInfoPtr->signFunction;
		capabilityInfo->sigCheckFunction = mechanismInfoPtr->sigCheckFunction;
		}

	return( ( CAPABILITY_INFO * ) capabilityInfo );
	}

/* Set the capability information based on device capabilities.  Since
   CryptoAPI devices can have assorted capabilities, we have to build this 
   up on the fly rather than using a fixed table like the built-in 
   capabilities */

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
	CRYPTOAPI_INFO *cryptoapiInfo = deviceInfo->deviceCryptoAPI;
	CAPABILITY_INFO *capabilityListTail = \
				( CAPABILITY_INFO * ) deviceInfo->capabilityInfo;
	PROV_ENUMALGS_EX capiAlgoInfo;
	int length = sizeof( PROV_ENUMALGS_EX );

	assert( sizeof( CAPABILITY_INFO ) == sizeof( VARIABLE_CAPABILITY_INFO ) );

	/* Step through each available CryptoAPI algorithm type adding the 
	   appropriate cryptlib capability for it */
	if( !pCryptGetProvParam( cryptoapiInfo->hProv, PP_ENUMALGS_EX, 
							 ( BYTE * ) &capiAlgoInfo, &length, CRYPT_FIRST ) )
		return( CRYPT_ERROR );
	do
		{
		CAPABILITY_INFO *newCapability, *capabilityListPtr;
		CRYPT_ALGO_TYPE cryptAlgo;
		int i;

		/* Check whether this algorithm type corresponds to a cryptlib
		   capability */
		for( i = 0; mechanismInfo[ i ].cryptAlgo != CRYPT_ALGO_NONE; i++ )
			if( mechanismInfo[ i ].algoID == capiAlgoInfo.aiAlgid || \
				( mechanismInfo[ i ].altAlgoID != CRYPT_ERROR && \
				  mechanismInfo[ i ].altAlgoID == capiAlgoInfo.aiAlgid ) )
				break;
		if( mechanismInfo[ i ].cryptAlgo == CRYPT_ALGO_NONE )
			continue;
		cryptAlgo = mechanismInfo[ i ].cryptAlgo;

		/* Check whether this is a variation of an existing capability */
		for( capabilityListPtr = ( CAPABILITY_INFO * ) deviceInfo->capabilityInfo; 
			 capabilityListPtr != NULL && \
				capabilityListPtr->cryptAlgo != cryptAlgo; 
			 capabilityListPtr = capabilityListPtr->next );
		if( capabilityListPtr != NULL )
			{
			addCapability( deviceInfo, &capiAlgoInfo, &mechanismInfo[ i ], 
						   capabilityListPtr );
			continue;
			}

		/* Add capabilities for all mechanisms corresponding to the current
		   CryptoAPI algorithm type.  If the assertion below triggers then 
		   the CryptoAPI provider is broken since it's returning 
		   inconsistent information such as illegal key length data, 
		   conflicting algorithm information, etc etc.  This assertion is 
		   included here to detect buggy drivers early on rather than 
		   forcing users to step through the CryptoAPI glue code to find out 
		   why an operation is failing.
		   
		   Because some providers mapped down to tinkertoy smart cards 
		   support only the bare minimum functionality (e.g.RSA private key 
		   ops and nothing else), we allow asymmetric functionality for 
		   PKCs */
		newCapability = addCapability( deviceInfo, &capiAlgoInfo, 
									   &mechanismInfo[ i ], NULL );
		if( newCapability == NULL )
			break;
		assert( capabilityInfoOK( newCapability, 
					( newCapability->cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
					  newCapability->cryptAlgo <= CRYPT_ALGO_LAST_PKC ) ? \
					  TRUE : FALSE ) );
		if( deviceInfo->capabilityInfo == NULL )
			deviceInfo->capabilityInfo = newCapability;
		else
			capabilityListTail->next = newCapability;
		capabilityListTail = newCapability;
		}
	while( pCryptGetProvParam( cryptoapiInfo->hProv, PP_ENUMALGS_EX, 
							   ( BYTE * ) &capiAlgoInfo, &length, 0 ) );

	return( ( deviceInfo->capabilityInfo == NULL ) ? CRYPT_ERROR : CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Mechanisms supported by CryptoAPI devices.  These are actually cryptlib 
   native mechanisms since many aren't supported by CryptoAPI, but not the 
   full set supported by the system device since functions like private key 
   export aren't available except in the nonstandard blob format invented 
   by Microsoft.  The list is sorted in order of frequency of use in order 
   to make lookups a bit faster */

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

int setDeviceCryptoAPI( DEVICE_INFO *deviceInfo, const char *name, 
						const int nameLength )
	{
	/* Make sure that the CryptoAPI driver DLL is loaded */
	if( hCryptoAPI == NULL_HINSTANCE )
		return( CRYPT_ERROR_OPEN );

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
#endif /* USE_CRYPTOAPI */
