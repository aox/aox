/****************************************************************************
*																			*
*							cryptlib Fortezza Routines						*
*						Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

/* This file contains its own version of the various Fortezza definitions and
   values to avoid potential copyright problems with redistributing the
   Fortezza interface library header files, and because they were typed in
   from the (exportable) printed manuals rather than through access to any
   original code */

#define PKC_CONTEXT		/* Indicate that we're working with PKC context */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "device.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/device.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* Uncomment the following to fake out writes to the card.  This makes 
   testing easier since it allows the code to be debugged without messing up 
   data stored on the card when the program is terminated halfway through an 
   update */

/* #define NO_UPDATE	*/

/* Return codes */

#define CI_OK				0	/* OK */
#define CI_FAIL				1	/* Generic failure */
#define CI_INV_STATE		9	/* Device in invalid state for this fn.*/
#define CI_EXEC_FAIL		10	/* Command execution failed */
#define CI_NO_KEY			11	/* No key loaded */
#define CI_NO_IV			12	/* No IV loaded */
#define CI_NO_X				13	/* No DSA x value loaded */
#define CI_NO_CARD			-20	/* Card not present */
#define CI_BAD_CARD			-30	/* Invalid or malfunctioning card */
#define CI_BAD_TUPLES		-44	/* Bad information in card */

/* Constants */

#define CI_NULL_FLAG		0	/* No operation */

#define CI_PIN_SIZE			12	/* Maximum size of PIN */
#define CI_NAME_SIZE		32	/* Maximum size of name */
#define CI_CERT_SIZE		2048/* Maximum size of certificate */
#define CI_CERT_NAME_SIZE	32	/* Maximum size of cert label */

#define CI_SSO_PIN			37	/* SSO PIN */
#define CI_USER_PIN			42	/* User PIN */

#define CI_KEA_TYPE			5	/* KEA algorithm */
#define CI_DSA_TYPE			10	/* DSA algorithm */
#define CI_DSA_KEA_TYPE		15	/* DSA+KEA algorithm */

#define CI_INITIATOR_FLAG	0	/* Flag for KEA initiator */
#define CI_RECIPIENT_FLAG	1	/* Flag for KEA responder */

#define CI_ENCRYPT_TYPE		0	/* Cipher mode = encryption */
#define CI_DECRYPT_TYPE		1	/* Cipher mode = decryption */

#define CI_ECB64_MODE		0	/* Skipjack/ECB */
#define CI_CBC64_MODE		1	/* Skipjack/CBC */
#define CI_OFB64_MODE		2	/* Skipjack/OFB */
#define CI_CFB64_MODE		3	/* Skipjack/CFB */

#define CI_POWER_UP			0	/* Initialising card */
#define CI_UNINITIALIZED	1	/* Uninitialized/zeroized with z/PIN entered */
#define CI_INITIALIZED		2	/* Initialized card */
#define CI_SSO_INITIALIZED	3	/* SSO PIN loaded */
#define CI_LAW_INITIALIZED	4	/* LAW/CAW init'd (i.e. user certs loaded) */
#define CI_USER_INITIALIZED	5	/* User PIN loaded */
#define CI_STANDBY			6	/* Wait for personality to be set */
#define CI_READY			7	/* Ready for use */
#define CI_ZEROIZED			8	/* Zeroized */
#define CI_INTERNAL_FAILURE	-1	/* Bang */

/* Data types */

typedef BYTE *CI_DATA;				/* Pointer to plaintext/ciphertext */
typedef BYTE CI_PIN[ CI_PIN_SIZE + 4];	/* Longword-padded PIN */
typedef BYTE CI_CERT_STR[ CI_CERT_NAME_SIZE + 4 ];	/* Certificate label */
typedef BYTE CI_CERTIFICATE[ 2048 ];/* Certificate */
typedef BYTE CI_IV[ 24 ];			/* LEAF + IV */
typedef BYTE CI_P[ 128 ];			/* DSA p parameter */
typedef BYTE CI_Q[ 20 ];			/* DSA q parameter */
typedef BYTE CI_G[ 128 ];			/* DSA g paramter */
typedef BYTE CI_Y[ 128 ];			/* DSA y value */
typedef BYTE CI_HASHVALUE[ 20 ];	/* SHA-1 hash value */
typedef BYTE CI_SIGNATURE[ 40 ];	/* DSA signature value */
typedef BYTE CI_RA[ 128 ];			/* KSA Ra value */
typedef BYTE CI_RB[ 128 ];			/* KSA Rb value */
typedef BYTE CI_KEY[ 12 ];			/* KEA-wrapped Skipjack key */
typedef BYTE CI_RANDOM[ 20 ];		/* Random data */
typedef BYTE CI_RANDSEED[ 8 ];		/* Random seed value */
typedef BYTE CI_KS[ 10 ];			/* Storage key */
typedef BYTE CI_TIME[ 16 ];			/* Time value */
typedef unsigned int CI_STATE, *CI_STATE_PTR;	/* Device state */
typedef struct {
	int CertificateIndex;			/* Cert.number */
	CI_CERT_STR CertLabel;			/* Personality label */
	} CI_PERSON, *CI_PERSON_PTR;
typedef struct {
	int LibraryVersion;				/* CI lib.version */
	int ManufacturerVersion;		/* Hardware version */
	char ManufacturerName[ CI_NAME_SIZE + 4 ];	/* Manuf.name */
	char ProductName[ CI_NAME_SIZE + 4 ];	/* Product name */
	char ProcessorType[ CI_NAME_SIZE + 4 ];	/* CPU type */
	unsigned long UserRAMSize;		/* Bytes of user RAM */
	unsigned long LargestBlockSize;	/* Max.single data block size */
	int KeyRegisterCount;			/* Number of key registers */
	int CertificateCount;			/* Max.number of certificates */
	int CryptoCardFlag;				/* Card present if nonzero */
	int ICDVersion;					/* ICD compliance level */
	int ManufacturerSWVer;			/* Device's firmware version */
	int DriverVersion;				/* Device driver version */
	} CI_CONFIG, *CI_CONFIG_PTR;

/* Various constants not defined in the Fortezza driver code */

#define FORTEZZA_IVSIZE		24			/* Size of LEAF+IV */

#ifdef USE_FORTEZZA

/* Return a pointer to the n-th personality in a personality list */

#define getPersonality( fortezzaInfo, index ) \
		( &( ( ( CI_PERSON * ) fortezzaInfo->personalities )[ index ] ) )

/* Prototypes for functions in cryptctx.c */

const void *findCapabilityInfo( const void *capabilityInfoPtr,
								const CRYPT_ALGO_TYPE cryptAlgo );

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

/* The number of sockets present in the system */

static int noSockets;

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on most
   systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hFortezza = NULL_HINSTANCE;

typedef int ( *CI_CHANGEPIN )( int PINType, CI_PIN pOldPIN, CI_PIN pNewPIN );
typedef int ( *CI_CHECKPIN )( int PINType, CI_PIN pPIN );
typedef int ( *CI_CLOSE )( unsigned int Flags, int SocketIndex );
typedef int ( *CI_DECRYPT )( unsigned int CipherSize, CI_DATA pCipher,
							 CI_DATA pPlain );
typedef int ( *CI_DELETECERTIFICATE )( int CertificateIndex );
typedef int ( *CI_DELETEKEY )( int RegisterIndex );
typedef int ( *CI_ENCRYPT )( unsigned int PlainSize, CI_DATA pPlain,
							 CI_DATA pCipher );
typedef int ( *CI_GENERATEIV )( CI_IV pIV );
typedef int ( *CI_GENERATEMEK )( int RegisterIndex, int Reserved );
typedef int ( *CI_GENERATERA )( CI_RA pRa );
typedef int ( *CI_GENERATERANDOM )( CI_RANDOM pRandom );
typedef int ( *CI_GENERATETEK )( int Flags, int RegisterIndex, CI_RA Ra, 
								 CI_RB Rb, unsigned int YSize, CI_Y pY );
typedef int ( *CI_GENERATEX )( int CertificateIndex, int AlgorithmType,
							   unsigned int PAndGSize, unsigned int QSize,
							   CI_P pP, CI_Q pQ, CI_G pG, unsigned int YSize,
							   CI_Y pY );
typedef int ( *CI_GETCERTIFICATE )( int CertificateIndex, 
									CI_CERTIFICATE pCertificate );
typedef int ( *CI_GETCONFIGURATION )( CI_CONFIG_PTR pConfiguration );
typedef int ( *CI_GETPERSONALITYLIST )( int EntryCount, 
										CI_PERSON pPersonalityList[] );
typedef int ( *CI_GETSTATE )( CI_STATE_PTR pState );
typedef int ( *CI_GETTIME )( CI_TIME pTime );
typedef int ( *CI_INITIALIZE )( int *SocketCount );
typedef int ( *CI_LOADCERTIFICATE )( int CertificateIndex, CI_CERT_STR pLabel, 
									 CI_CERTIFICATE pCertificate, long Reserved );
typedef int ( *CI_LOADINITVALUES )( CI_RANDSEED pRandSeed, CI_KS pKs );
typedef int ( *CI_LOADIV )( CI_IV pIV );
typedef int ( *CI_LOCK )( int Flags );
typedef int ( *CI_OPEN )( unsigned int *Flags, int SocketIndex );
typedef int ( *CI_RESET )( void );
typedef int ( *CI_SETKEY )( int RegisterIndex );
typedef int ( *CI_SETMODE )( int CryptoType, int CryptoMode );
typedef int ( *CI_SETPERSONALITY )( int CertificateIndex );
typedef int ( *CI_SIGN )( CI_HASHVALUE pHashValue, CI_SIGNATURE pSignature );
typedef int ( *CI_TERMINATE )( void );
typedef int ( *CI_UNLOCK )( void );
typedef int ( *CI_UNWRAPKEY )( int UnwrapIndex, int KeyIndex, CI_KEY pKey );
typedef int ( *CI_VERIFYSIGNATURE )( CI_HASHVALUE pHashValue, unsigned int YSize,
									 CI_Y pY, CI_SIGNATURE pSignature );
typedef int ( *CI_WRAPKEY )( int WrapIndex, int KeyIndex, CI_KEY pKey );
typedef int ( *CI_ZEROIZE )( void );
static CI_CHANGEPIN pCI_ChangePIN = NULL;
static CI_CHECKPIN pCI_CheckPIN = NULL;
static CI_CLOSE pCI_Close = NULL;
static CI_DECRYPT pCI_Decrypt = NULL;
static CI_DELETECERTIFICATE pCI_DeleteCertificate = NULL;
static CI_DELETEKEY pCI_DeleteKey = NULL;
static CI_ENCRYPT pCI_Encrypt = NULL;
static CI_GENERATEIV pCI_GenerateIV = NULL;
static CI_GENERATEMEK pCI_GenerateMEK = NULL;
static CI_GENERATERA pCI_GenerateRa = NULL;
static CI_GENERATERANDOM pCI_GenerateRandom = NULL;
static CI_GENERATETEK pCI_GenerateTEK = NULL;
static CI_GENERATEX pCI_GenerateX = NULL;
static CI_GETCERTIFICATE pCI_GetCertificate = NULL;
static CI_GETCONFIGURATION pCI_GetConfiguration = NULL;
static CI_GETPERSONALITYLIST pCI_GetPersonalityList = NULL;
static CI_GETSTATE pCI_GetState = NULL;
static CI_GETTIME pCI_GetTime = NULL;
static CI_INITIALIZE pCI_Initialize = NULL;
static CI_LOADCERTIFICATE pCI_LoadCertificate = NULL;
static CI_LOADINITVALUES pCI_LoadInitValues = NULL;
static CI_LOADIV pCI_LoadIV = NULL;
static CI_LOCK pCI_Lock = NULL;
static CI_OPEN pCI_Open = NULL;
static CI_RESET pCI_Reset = NULL;
static CI_SETKEY pCI_SetKey = NULL;
static CI_SETMODE pCI_SetMode = NULL;
static CI_SETPERSONALITY pCI_SetPersonality = NULL;
static CI_SIGN pCI_Sign = NULL;
static CI_TERMINATE pCI_Terminate = NULL;
static CI_UNLOCK pCI_Unlock = NULL;
static CI_UNWRAPKEY pCI_UnwrapKey = NULL;
static CI_VERIFYSIGNATURE pCI_VerifySignature = NULL;
static CI_WRAPKEY pCI_WrapKey = NULL;
static CI_ZEROIZE pCI_Zeroize = NULL;

/* Depending on whether we're running under Win16 or Win32 we load the device
   driver under a different name */

#ifdef __WIN16__
  #define FORTEZZA_LIBNAME	"TSSP.DLL"
#else
  #define FORTEZZA_LIBNAME	"TSSP32.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary card drivers */

static void initCapabilities( void );

int deviceInitFortezza( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */
	static BOOLEAN initCalled = FALSE;

	/* If we've previously tried to init the drivers, don't try it again */
	if( initCalled )
		return( CRYPT_OK );
	initCalled = TRUE;
	initCapabilities();

	/* Obtain a handle to the device driver module */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hFortezza = LoadLibrary( FORTEZZA_LIBNAME );
	SetErrorMode( errorMode );
	if( hFortezza < HINSTANCE_ERROR )
		{
		hFortezza = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}
#else
	if( ( hFortezza = LoadLibrary( FORTEZZA_LIBNAME ) ) == NULL_HINSTANCE )
		return( CRYPT_ERROR );
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pCI_ChangePIN = ( CI_CHANGEPIN ) GetProcAddress( hFortezza, "CI_ChangePIN" );
	pCI_CheckPIN = ( CI_CHECKPIN ) GetProcAddress( hFortezza, "CI_CheckPIN" );
	pCI_Close = ( CI_CLOSE ) GetProcAddress( hFortezza, "CI_Close" );
	pCI_Decrypt = ( CI_DECRYPT ) GetProcAddress( hFortezza, "CI_Decrypt" );
	pCI_DeleteCertificate = ( CI_DELETECERTIFICATE ) GetProcAddress( hFortezza, "CI_DeleteCertificate" );
	pCI_DeleteKey = ( CI_DELETEKEY ) GetProcAddress( hFortezza, "CI_DeleteKey" );
	pCI_Encrypt = ( CI_ENCRYPT ) GetProcAddress( hFortezza, "CI_Encrypt" );
	pCI_GenerateIV = ( CI_GENERATEIV ) GetProcAddress( hFortezza, "CI_GenerateIV" );
	pCI_GenerateMEK = ( CI_GENERATEMEK ) GetProcAddress( hFortezza, "CI_GenerateMEK" );
	pCI_GenerateRa = ( CI_GENERATERA ) GetProcAddress( hFortezza, "CI_GenerateRa" );
	pCI_GenerateRandom = ( CI_GENERATERANDOM ) GetProcAddress( hFortezza, "CI_GenerateRandom" );
	pCI_GenerateTEK = ( CI_GENERATETEK ) GetProcAddress( hFortezza, "CI_GenerateTEK" );
	pCI_GenerateX = ( CI_GENERATEX ) GetProcAddress( hFortezza, "CI_GenerateX" );
	pCI_GetCertificate = ( CI_GETCERTIFICATE ) GetProcAddress( hFortezza, "CI_GetCertificate" );
	pCI_GetConfiguration = ( CI_GETCONFIGURATION ) GetProcAddress( hFortezza, "CI_GetConfiguration" );
	pCI_GetPersonalityList = ( CI_GETPERSONALITYLIST ) GetProcAddress( hFortezza, "CI_GetPersonalityList" );
	pCI_GetState = ( CI_GETSTATE ) GetProcAddress( hFortezza, "CI_GetState" );
	pCI_GetTime = ( CI_GETTIME ) GetProcAddress( hFortezza, "CI_GetTime" );
	pCI_Initialize = ( CI_INITIALIZE ) GetProcAddress( hFortezza, "CI_Initialize" );
	pCI_LoadCertificate = ( CI_LOADCERTIFICATE ) GetProcAddress( hFortezza, "CI_LoadCertificate" );
	pCI_LoadInitValues = ( CI_LOADINITVALUES ) GetProcAddress( hFortezza, "CI_LoadInitValues" );
	pCI_LoadIV = ( CI_LOADIV ) GetProcAddress( hFortezza, "CI_LoadIV" );
	pCI_Lock = ( CI_LOCK ) GetProcAddress( hFortezza, "CI_Lock" );
	pCI_Open = ( CI_OPEN ) GetProcAddress( hFortezza, "CI_Open" );
	pCI_Reset = ( CI_RESET ) GetProcAddress( hFortezza, "CI_Reset" );
	pCI_SetKey = ( CI_SETKEY ) GetProcAddress( hFortezza, "CI_SetKey" );
	pCI_SetMode = ( CI_SETMODE ) GetProcAddress( hFortezza, "CI_SetMode" );
	pCI_SetPersonality = ( CI_SETPERSONALITY ) GetProcAddress( hFortezza, "CI_SetPersonality" );
	pCI_Sign = ( CI_SIGN ) GetProcAddress( hFortezza, "CI_Sign" );
	pCI_Terminate = ( CI_TERMINATE ) GetProcAddress( hFortezza, "CI_Terminate" );
	pCI_Unlock = ( CI_UNLOCK ) GetProcAddress( hFortezza, "CI_Unlock" );
	pCI_UnwrapKey = ( CI_UNWRAPKEY ) GetProcAddress( hFortezza, "CI_UnwrapKey" );
	pCI_VerifySignature = ( CI_VERIFYSIGNATURE ) GetProcAddress( hFortezza, "CI_VerifySignature" );
	pCI_WrapKey = ( CI_WRAPKEY ) GetProcAddress( hFortezza, "CI_WrapKey" );
	pCI_Zeroize = ( CI_ZEROIZE ) GetProcAddress( hFortezza, "CI_Zeroize" );

	/* Make sure that we got valid pointers for every device function */
	if( pCI_ChangePIN == NULL || pCI_CheckPIN == NULL || pCI_Close == NULL ||
		pCI_Decrypt == NULL || pCI_DeleteCertificate == NULL || 
		pCI_DeleteKey == NULL || pCI_Encrypt == NULL || 
		pCI_GenerateIV == NULL || pCI_GenerateMEK == NULL || 
		pCI_GenerateRa == NULL || pCI_GenerateRandom == NULL || 
		pCI_GenerateTEK == NULL || pCI_GenerateX == NULL || 
		pCI_GetCertificate == NULL || pCI_GetConfiguration == NULL || 
		pCI_GetPersonalityList == NULL || pCI_GetState == NULL || 
		pCI_GetTime == NULL || pCI_Initialize == NULL || 
		pCI_LoadCertificate == NULL || pCI_LoadInitValues == NULL || 
		pCI_LoadIV == NULL || pCI_Lock == NULL || pCI_Open == NULL || 
		pCI_Reset == NULL || pCI_SetKey == NULL || pCI_SetMode == NULL || 
		pCI_SetPersonality == NULL || pCI_Sign == NULL || 
		pCI_Terminate == NULL || pCI_Unlock == NULL || 
		pCI_UnwrapKey == NULL || pCI_VerifySignature == NULL || 
		pCI_WrapKey == NULL || pCI_Zeroize == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hFortezza );
		hFortezza = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}

	/* Initialise the Fortezza library */
	if( pCI_Initialize( &noSockets ) != CI_OK )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hFortezza );
		hFortezza = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

void deviceEndFortezza( void )
	{
	if( hFortezza != NULL_HINSTANCE )
		{
		pCI_Terminate();
		FreeLibrary( hFortezza );
		}
	hFortezza = NULL_HINSTANCE;
	}

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a Fortezza-specific error to a cryptlib error */

static int mapError( const int errorCode, const int defaultError )
	{
	switch( errorCode )
		{
		case CI_OK:
			return( CRYPT_OK );
		case CI_NO_CARD:
		case CI_BAD_CARD:
			return( CRYPT_ERROR_SIGNALLED );
		case CI_INV_STATE:
			return( CRYPT_ERROR_PERMISSION );
		case CI_NO_IV:
		case CI_NO_KEY:
			return( CRYPT_ERROR_NOTINITED );
		case CI_EXEC_FAIL:
			return( CRYPT_ERROR_FAILED );
		}

	return( defaultError );
	}

/* Set up a PIN in the format required by the Fortezza driver */

static void initPIN( CI_PIN pinBuffer, const void *pin, const int pinLength )
	{
	memset( pinBuffer, 0, sizeof( CI_PIN ) );
	if( pinLength > 0 )
		memcpy( pinBuffer, pin, pinLength );
	pinBuffer[ pinLength ] = '\0';	/* Ensure PIN is null-terminated */	
	}

/* Extract the time from a time string */

static time_t getTokenTime( CI_TIME cardTime )
	{
	STREAM stream;
	BYTE buffer[ 32 + 8 ];
	time_t theTime = MIN_TIME_VALUE + 1;
	int length, status;

	/* Convert the token time to an ASN.1 time string that we can read using
	   the standard ASN.1 routines by writing a dummy time value and inserting 
	   the token's time string in its place */
	sMemOpen( &stream, buffer, 32 );
	writeGeneralizedTime( &stream, theTime, DEFAULT_TAG );
	length = stell( &stream );
	sMemDisconnect( &stream );
	memcpy( buffer + 2, cardTime, 14 );
	sMemConnect( &stream, buffer, length );
	status = readGeneralizedTime( &stream, &theTime );
	sMemDisconnect( &stream );
	
	return( ( cryptStatusOK( status ) ) ? theTime : 0 );
	}

/* Find a free key register */

static int findFreeKeyRegister( const FORTEZZA_INFO *fortezzaInfo )
	{
	int mask = 2, i;

	/* Search the register-in-use flags for a free register */
	for( i = 1; i < fortezzaInfo->keyRegisterCount && \
				i < FAILSAFE_ITERATIONS_MED; i++ )
		{
		if( !( fortezzaInfo->keyRegisterFlags & mask ) )
			break;
		mask <<= 1;
		}
	if( i >= FAILSAFE_ITERATIONS_MED )
		retIntError();
	
	return( ( i >= fortezzaInfo->keyRegisterCount ) ? \
			CRYPT_ERROR_OVERFLOW : i );
	}

/* Find a free key/certificate slot */

static int findFreeCertificate( const FORTEZZA_INFO *fortezzaInfo )
	{
	CI_PERSON *personalityList = fortezzaInfo->personalities;
	int certIndex;

	for( certIndex = 0; certIndex < fortezzaInfo->personalityCount && \
						certIndex < FAILSAFE_ITERATIONS_MED; 
		 certIndex++ )
		{
		if( personalityList[ certIndex ].CertLabel[ 0 ] == '\0' )
			return( certIndex );
		}
	if( certIndex >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	return( CRYPT_ERROR );
	}

/* Set a certificate/personality label using the labelling system defined 
   in SDN.605.  This is somewhat ad hoc since non-DOD Fortezza usage won't 
   follow the somewhat peculiar certification heirarchy designed for DOD/
   government use, so we just mark a cert as CA/individual rather than CA/
   PCA/PAA.  In addition we select between organisational and individual 
   certs based on whether an organizationName or organizationalUnitName is 
   present */

static void getCertificateLabel( const int certIndex, const int parentIndex,
								 const CRYPT_CERTIFICATE iCryptCert, 
								 const BOOLEAN newEntry, char *label,
								 const int labelMaxLen )
	{
	MESSAGE_DATA msgData;
	int value, status;

	memset( label, 0, sizeof( CI_CERT_STR ) );

	/* If this is certificate slot 0, it's a PAA cert being installed by the 
	   SSO */
	if( certIndex <= 0 )
		{
		memcpy( label, "PAA1FFFF", 8 );

		return;
		}

	/* Check to see whether it's a CA cert.  If it is, label it as a
	   generic CA key (which encompasses all of CA/PCA/PAA) */
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CA );
	if( cryptStatusOK( status ) && value > 0 )
		{
		sPrintf_s( label, labelMaxLen, "CAX1FF%02X", 
				   ( parentIndex != CRYPT_UNUSED ) ? parentIndex : 0xFF );
		
		return;
		}

	/* If there's a key agreement key usage, it must be KEA */
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_KEYUSAGE );
	if( cryptStatusOK( status ) && \
		( value & ( CRYPT_KEYUSAGE_KEYAGREEMENT | \
					CRYPT_KEYUSAGE_ENCIPHERONLY | \
					CRYPT_KEYUSAGE_DECIPHERONLY ) ) )
		{
		sPrintf_s( label, labelMaxLen, "KEAKFF%02X", 
				   ( parentIndex != CRYPT_UNUSED ) ? parentIndex : 0xFF );

		return;
		}

	/* Select the SubjectName as the current DN and check whether there's 
	   organisation-related components present.  Given the dog's breakfast 
	   of DN components present in most certs this will probably mis-
	   identify individual keys as organisational ones some of the time, 
	   but it's unlikely that anything distinguishes between I and O keys 
	   anyway */
	value = CRYPT_UNUSED;
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, &value, 
					 CRYPT_CERTINFO_SUBJECTNAME );
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CERTINFO_ORGANIZATIONNAME );
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, 
								  CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
		}
	if( cryptStatusError( status ) )
		sPrintf_s( label, labelMaxLen, "DSAIFF%02X", 
				   ( parentIndex != CRYPT_UNUSED ) ? parentIndex : 0xFF );
	else
		sPrintf_s( label, labelMaxLen, "DSAOFF%02X", 
				   ( parentIndex != CRYPT_UNUSED ) ? parentIndex : 0xFF );

	/* If it's a completely new entry (i.e. one that doesn't correspond to a 
	   private key), mark it as a cert-only key */
	if( newEntry > 0 )
		label[ 3 ] = 'X';
	}

/* Find a certificate/personality using the labelling system defined in
   SDN.605 */

static int findCertificateFromLabel( const FORTEZZA_INFO *fortezzaInfo, 
									 const char *label, 
									 const int labelLength )
	{
	static const char *names[] = { 
		"DSAI", "DSAO", "DSAX",		/* DSA individual, org, cert-only */
		"KEAK", "KEAX",				/* KEA, cert-only */
		"CAX1", "PCA1", "PAA1",		/* DSA CA, PCA, PAA */
		"INKS", "ONKS",				/* Legacy DSA+KEA individual, org */
		"INKX", "ONKX",				/* Legacy KEA individual, org */
		NULL, NULL };
	CI_PERSON *personalityList = fortezzaInfo->personalities;
	int labelIndex, certIndex;

	/* If a label is specified, look for the cert for the personality with 
	   the given label */
	if( label != NULL )
		{
		for( certIndex = 0; certIndex < fortezzaInfo->personalityCount && \
							certIndex < FAILSAFE_ITERATIONS_MED; \
			 certIndex++ )
			{
			if( !memcmp( personalityList[ certIndex ].CertLabel + 8, label, 
						 labelLength ) )
				return( certIndex );
			}
		if( certIndex >= FAILSAFE_ITERATIONS_MED )
			retIntError();

		return( CRYPT_ERROR );
		}

	/* No label given, look for the certificate in order of likeliness.  
	   First we look for a personal certificate with a signing key, if that
	   fails we look for an organisational certificate with a signing key */
	for( labelIndex = 0; names[ labelIndex ] != NULL && \
						 labelIndex < FAILSAFE_ARRAYSIZE( names, char * ); 
		 labelIndex++ )
		{
		for( certIndex = 0; certIndex < fortezzaInfo->personalityCount && \
							certIndex < FAILSAFE_ITERATIONS_MED; \
			 certIndex++ )
			{
			if( !strncmp( personalityList[ certIndex ].CertLabel, \
						  names[ labelIndex ], 4 ) )
				return( certIndex );
			}
		if( certIndex >= FAILSAFE_ITERATIONS_MED )
			retIntError();
		}
	if( labelIndex >= FAILSAFE_ARRAYSIZE( names, char * ) )
		retIntError();

	return( CRYPT_ERROR );
	}

/* Build a list of hashes of all certificates on the card */

static void getCertificateInfo( FORTEZZA_INFO *fortezzaInfo )
	{
	CI_PERSON *personalityList = fortezzaInfo->personalities;
	CI_HASHVALUE *hashList = fortezzaInfo->certHashes;
	CI_CERTIFICATE certificate;
	HASHFUNCTION hashFunction;
	int certIndex, certSize;

	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
	memset( hashList, 0, fortezzaInfo->personalityCount * sizeof( CI_HASHVALUE ) );
	for( certIndex = 0; certIndex < fortezzaInfo->personalityCount && \
						certIndex < FAILSAFE_ITERATIONS_MED; certIndex++ )
		{
		STREAM stream;
		int status;

		/* If there's no cert present at this location, continue */
		if( personalityList[ certIndex ].CertLabel[ 0 ] == '\0' || \
			pCI_GetCertificate( certIndex, certificate ) != CI_OK )
			continue;

		/* Get the hash of the certificate data.  Sometimes the card can
		   contain existing cert entries with garbage values so we don't 
		   hash the cert data if it doesn't look right */
		sMemConnect( &stream, certificate, sizeof( CI_CERTIFICATE ) );
		status = readSequence( &stream, &certSize );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) || \
			certSize < 256 || certSize > CI_CERT_SIZE - 4 )
			continue;
		hashFunction( NULL, hashList[ certIndex ], sizeof( CI_HASHVALUE ),
					  certificate, ( int ) sizeofObject( certSize ), 
					  HASH_ALL );
		}
	if( certIndex >= FAILSAFE_ITERATIONS_MED )
		retIntError_Void();
	fortezzaInfo->certHashesInitialised = TRUE;
	}

/* Find a certificate based on its hash value */

static int findCertFromHash( const FORTEZZA_INFO *fortezzaInfo,
							 const void *certHash )
	{
	CI_HASHVALUE *hashList = fortezzaInfo->certHashes;
	int certIndex;

	for( certIndex = 0; certIndex < fortezzaInfo->personalityCount && \
						certIndex < FAILSAFE_ITERATIONS_MED; \
		 certIndex++ )
		{
		if( !memcmp( hashList[ certIndex ], certHash, 
			sizeof( CI_HASHVALUE ) ) )
			return( certIndex );
		}
	if( certIndex >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	return( CRYPT_ERROR_NOTFOUND );
	}

/* Update certificate/personality information to reflect changes made in the 
   device */

static void updateCertificateInfo( FORTEZZA_INFO *fortezzaInfo, 
								   const int certIndex, 
								   const void *certificate, 
								   const int certSize, const char *label )
	{
	CI_PERSON *personality = getPersonality( fortezzaInfo, certIndex );
	CI_HASHVALUE *hashList = fortezzaInfo->certHashes;

	/* Update the hash for the certificate/raw key */
	if( certificate != NULL )
		{
		HASHFUNCTION hashFunction;

		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
		hashFunction( NULL, hashList[ certIndex ], sizeof( CI_HASHVALUE ),
					  ( void * ) certificate, certSize, HASH_ALL );
		}
	else
		/* There's no cert present at this location (for example because 
		   we've just deleted it), make sure that the hash is zero */
		memset( hashList[ certIndex ], 0, sizeof( CI_HASHVALUE ) );

	/* Update the label for the certificate/personality */
	memset( personality->CertLabel, 0, sizeof( CI_CERT_STR ) );
	strcpy( personality->CertLabel, label );
	}

/* Set up certificate/raw key information and load it into the card */

static int updateCertificate( FORTEZZA_INFO *fortezzaInfo, const int certIndex, 
							  const CRYPT_CERTIFICATE iCryptCert, 
							  const char *labelData, const int parentIndex )
	{
	CI_PERSON *personality = getPersonality( fortezzaInfo, certIndex );
	CI_CERTIFICATE certificate;
	CI_CERT_STR label;
	MESSAGE_DATA msgData;
	int certificateLength, status;

	/* If we're trying to load the PAA cert, the device must be in the SSO 
	   initialised state */
	if( certIndex <= 0 )
		{
		CI_STATE deviceState;

		status = pCI_GetState( &deviceState );
		if( status != CI_OK || deviceState != CI_SSO_INITIALIZED )
			return( CRYPT_ERROR_PERMISSION );
		}

	/* Get the SDN.605 label for the cert */
	getCertificateLabel( certIndex, parentIndex, iCryptCert, 
						 personality->CertLabel[ 0 ] ? FALSE : TRUE, 
						 label, sizeof( CI_CERT_STR ) );

	/* If there's label data supplied (which happens for data-only certs 
	   with no associated personality), use that */
	if( labelData != NULL )
		strcpy( label + 8, labelData );
	else
		/* Reuse the existing label from the personality corresponding to
		   the cert */
		strcpy( label + 8, personality->CertLabel + 8 );

	/* Set up the certificate data and send it to the card */
	memset( certificate, 0, sizeof( CI_CERTIFICATE ) );
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData, 
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		certificateLength = msgData.length;
		if( certificateLength > sizeof( CI_CERTIFICATE ) )
			return( CRYPT_ERROR_OVERFLOW );
		setMessageData( &msgData, certificate, certificateLength );
		status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData,
								  CRYPT_CERTFORMAT_CERTIFICATE );
		}
	if( cryptStatusError( status ) )
		return( status );
#ifndef NO_UPDATE
	status = pCI_LoadCertificate( certIndex, label, certificate, 0 );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_FAILED ) );
#endif /* NO_UPDATE */

	/* Update the in-memory copy of the cert information */
	updateCertificateInfo( fortezzaInfo, certIndex, certificate, 
						   certificateLength, label );

	return( CRYPT_OK );
	}

static int updateRawKey( FORTEZZA_INFO *fortezzaInfo, const int certIndex, 
						 const void *rawKeyData, const int rawKeySize,
						 const char *labelData )
	{
	CI_CERT_STR label;
	CI_CERTIFICATE certificate;
	int status;

	/* Set the SDN.605 related certificate locator to indicate that no 
	   parent or sibling certificates are present for this key, and use the 
	   cryptlib U/E specifier "TEMP" to indicate a temporary key awaiting a 
	   certificate */
	strcpy( label, "TEMPFFFF" );
	strncpy( label + 8, labelData, 24 );

	/* Set up the raw key data and send it to the card */
	memset( certificate, 0, sizeof( CI_CERTIFICATE ) );
	memcpy( certificate, rawKeyData, rawKeySize );
#ifndef NO_UPDATE
	status = pCI_LoadCertificate( certIndex, label, certificate, 0 );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_FAILED ) );
#endif /* NO_UPDATE */

	/* Update the in-memory copy of the cert information */
	updateCertificateInfo( fortezzaInfo, certIndex, rawKeyData, 
						   rawKeySize, label );

	return( CRYPT_OK );
	}

/* Information about certs on the card.  The slot index and parent slot 
   index contain the mapping of cert positions in the chain to cert
   positions and parent cert positions in the card, the certPresent and
   personalityPresent flags indicate whether the cert is already present in 
   the card and whether the cert being added corresponds to a personality
   in the card rather than being a data-only cert (e.g. from a CA that
   issued the end-entity cert corresponding to a present personality) */

typedef struct {
	int index, parentIndex;		/* Pos.of cert and parent cert */
	BOOLEAN certPresent;		/* Whether cert present in card */
	BOOLEAN personalityPresent;	/* Whether cert corresponds to card pers.*/
	} CARDCERT_INFO;

/* Update a card using the certs in a cert chain */

static int updateCertChain( FORTEZZA_INFO *fortezzaInfo,
							const CRYPT_CERTIFICATE iCryptCert )
	{
	CI_PERSON *personalityList = fortezzaInfo->personalities;
	CARDCERT_INFO cardCertInfo[ 16 + 8 ];
	int chainIndex = -1, oldCertIndex, value, i, iterationCount = 0;

	/* Initialise the certificate index information and hashes for the certs
	   on the card if necessary.  certList[] contains the mapping of certs in
	   the chain to positions in the card, parentList[] contains the mapping
	   of certs in the chain to the position of their parents in the card */
	for( i = 0; i < 16; i++ )
		{
		memset( &cardCertInfo[ i ], 0, sizeof( CARDCERT_INFO ) );
		cardCertInfo[ i ].index = \
				cardCertInfo[ i ].parentIndex = CRYPT_UNUSED;
		}
	if( !fortezzaInfo->certHashesInitialised )
		getCertificateInfo( fortezzaInfo );

	/* Start at the top-level cert and work our way down, which ensures that
	   the CA certs appear first, and that if an update fails, the parent
	   cert pointers point to valid fields (since higher-level certs are
	   added first) */
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORLAST, CRYPT_CERTINFO_CURRENT_CERTIFICATE );

	/* Pass 1: Build an index of cert and parent cert positions in the card.  
	   Once this loop has completed, certList[] contains a mapping from cert 
	   chain position to position in the card, and parentList[] contains a 
	   mapping from cert chain position to parent cert position in the card */
	do
		{
		MESSAGE_DATA msgData;
		CI_HASHVALUE hash;
		BOOLEAN isPresent = FALSE;
		int certIndex;

		/* Increment the chain index.  We do this at the start of the loop 
		   since we start at the -1th position */
		chainIndex++;

		/* Get the hash for this cert and check whether it's already present */
		setMessageData( &msgData, &hash, sizeof( CI_HASHVALUE ) );
		if( cryptStatusError( \
			krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S,
							 &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA ) ) )
			return( CRYPT_ARGERROR_NUM1 );
		certIndex = findCertFromHash( fortezzaInfo, hash );
		if( !cryptStatusError( certIndex ) )
			isPresent = TRUE;

		/* Set the mapping from cert to parent cert position in the card.  
		   The cert at position 0 is the root cert */
		if( chainIndex > 0 )
			cardCertInfo[ chainIndex ].parentIndex = oldCertIndex;
		
		/* Set the mapping from cert to position in the card */
		if( isPresent )
			{
			cardCertInfo[ chainIndex ].index = certIndex;
			cardCertInfo[ chainIndex ].certPresent = TRUE;
			}
		else
			{
			int freeCertIndex;;

			/* Allocate this cert to the next free position in the card */
			for( freeCertIndex = 0; 
				 freeCertIndex < fortezzaInfo->personalityCount && \
					personalityList[ freeCertIndex ].CertLabel[ 0 ] != '\0' && \
					freeCertIndex < FAILSAFE_ITERATIONS_MED; 
				 freeCertIndex++ );
			if( freeCertIndex >= FAILSAFE_ITERATIONS_MED )
				retIntError();
			if( freeCertIndex >= fortezzaInfo->personalityCount )
				/* There's no more room for any new certificates in the 
				   card */
				return( CRYPT_ERROR_OVERFLOW );
			cardCertInfo[ chainIndex ].index = freeCertIndex;
			}

		/* Remember the just-assigned position in the card */
		oldCertIndex = cardCertInfo[ chainIndex ].index;
		}
	while( krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
							MESSAGE_VALUE_CURSORPREVIOUS,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED );
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	/* The last cert in the chain will either already be present or will be 
	   present in raw-key form.  If it's present in raw-key form the previous
	   code will add it as a pseudo-new cert, so we find the location of the
	   corresponding raw and set its index to the raw key position */
	if( !cardCertInfo[ chainIndex ].certPresent )
		{
		HASHFUNCTION hashFunction;
		MESSAGE_DATA msgData;
		BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ], keyDataBuffer[ 1024 + 8 ];
		int certIndex;

		/* Get the keyID for the leaf certificate */
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
		setMessageData( &msgData, keyDataBuffer, 1024 );
		if( cryptStatusError( \
			krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S,
							 &msgData, CRYPT_IATTRIBUTE_SPKI ) ) )
			return( CRYPT_ARGERROR_NUM1 );
		hashFunction( NULL, hash, CRYPT_MAX_HASHSIZE, keyDataBuffer, 
					  msgData.length, HASH_ALL );

		/* If we're not adding the cert as a data-only PAA cert in the 0-th
		   slot (which is a special case with no corresponding personality 
		   present), find the slot for the cert based on the location of the 
		   corresponding raw key.  If there's no raw key present, we can't 
		   add the chain, since it doesn't correspond to any known key or 
		   cert */
		if( cardCertInfo[ chainIndex ].index > 0 )
			{
			certIndex = findCertFromHash( fortezzaInfo, hash );
			if( cryptStatusError( certIndex ) )
				return( CRYPT_ERROR_NOTFOUND );
			cardCertInfo[ chainIndex ].index = certIndex;
			}
		cardCertInfo[ chainIndex ].personalityPresent = TRUE;
		}

	/* Pass 2: Update either the label or cert+label as required */
	value = CRYPT_CURSOR_LAST;
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, &value, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	value = CRYPT_CURSOR_PREVIOUS;
	chainIndex = 0;
	iterationCount = 0;
	do
		{
		CARDCERT_INFO *currentCertInfo = &cardCertInfo[ chainIndex++ ];
		char name[ CRYPT_MAX_TEXTSIZE + 1 + 8 ], *labelPtr = NULL;
		int status;

		/* If the cert is already present, make sure that the parent index 
		   info is correct */
		if( currentCertInfo->certPresent )
			{
			CI_CERTIFICATE certificate;
			const int certIndex = currentCertInfo->index;
			char buffer[ 16 + 8 ];
			int index;

			/* If the cert is present and the parent cert index is correct,
			   continue */
			if( ( sscanf( personalityList[ certIndex ].CertLabel + 6, 
						  "%02X", &index ) == 1 ) && \
				( currentCertInfo->parentIndex == index || \
				  currentCertInfo->parentIndex == CRYPT_UNUSED ) )
				continue;

			/* Update the parent cert index in the label, read the cert, and 
			   write it back out with the new label */
			sPrintf_s( buffer, 8, "%02X", currentCertInfo->parentIndex );
			memcpy( personalityList[ certIndex ].CertLabel + 6, buffer, 2 );
			status = pCI_GetCertificate( certIndex, certificate );
#ifndef NO_UPDATE
			if( status == CI_OK )
				status = pCI_LoadCertificate( certIndex, 
									personalityList[ certIndex ].CertLabel,
									certificate, 0 );
#endif /* NO_UPDATE */
			if( status != CI_OK )
				return( mapError( status, CRYPT_ERROR_WRITE ) );
			continue;
			}
		
		/* If we're adding a new cert for a non-present personality (that is,
		   a data-only CA cert from higher up in the chain that doesn't 
		   correspond to a personality on the card), get SubjectName 
		   information from the cert to use as the label and make sure that 
		   it's within the maximum allowed length.  Some certs don't have CN 
		   components, so we try for the OU instead.  If that also fails, we 
		   try for the O, and if that fails we  just use a dummy label 
		   identifying it as a generic CA cert */
		if( !currentCertInfo->personalityPresent )
			{
			MESSAGE_DATA msgData;

			value = CRYPT_UNUSED;
			krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, &value, 
							 CRYPT_CERTINFO_SUBJECTNAME );
			setMessageData( &msgData, name, CRYPT_MAX_TEXTSIZE );
			status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S,
							&msgData, CRYPT_CERTINFO_COMMONNAME );
			if( status == CRYPT_ERROR_NOTFOUND )
				status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
							&msgData, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
			if( status == CRYPT_ERROR_NOTFOUND )
				status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
							&msgData, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
			if( status == CRYPT_ERROR_NOTFOUND )
				strcpy( name, "CA certificate-only entry" );
			else
				name[ min( msgData.length, 24 ) ] = '\0';
			labelPtr = name;
			}

		/* Write the new cert and label */
		status = updateCertificate( fortezzaInfo, currentCertInfo->index, 
									iCryptCert, labelPtr, 
									currentCertInfo->parentIndex );
		if( cryptStatusError( status ) )
			return( status );
		}
	while( krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, &value,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED );
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Table of mechanisms supported by this device.  These are sorted in order 
   of frequency of use in order to make lookups a bit faster */

static int exportKEA( DEVICE_INFO *deviceInfo, MECHANISM_WRAP_INFO *mechanismInfo );
static int importKEA( DEVICE_INFO *deviceInfo, MECHANISM_WRAP_INFO *mechanismInfo );

static const MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_KEA, exportKEA },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_KEA, importKEA },
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }, { MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

/* Close a previously-opened session with the device.  We have to have this
   before the init function since it may be called by it if the init process
   fails */

static void shutdownFunction( DEVICE_INFO *deviceInfo )
	{
	FORTEZZA_INFO *fortezzaInfo = deviceInfo->deviceFortezza;

	/* Clear the personality list if it exists */
	if( fortezzaInfo->personalities != NULL )
		{
		zeroise( fortezzaInfo->personalities, 
				 fortezzaInfo->personalityCount * sizeof( CI_PERSON ) );
		clFree( "shutdownFunction", fortezzaInfo->personalities );
		fortezzaInfo->personalities = NULL;
		fortezzaInfo->personalityCount = 0;
		}
	if( fortezzaInfo->certHashes != NULL )
		{
		zeroise( fortezzaInfo->certHashes, 
				 fortezzaInfo->personalityCount * sizeof( CI_HASHVALUE ) );
		clFree( "shutdownFunction", fortezzaInfo->certHashes );
		fortezzaInfo->certHashes = NULL;
		fortezzaInfo->certHashesInitialised = FALSE;
		}

	/* Unlock the socket and close the session with the device */
	if( deviceInfo->flags & DEVICE_LOGGEDIN )
		{
		pCI_Unlock();
		deviceInfo->flags &= ~DEVICE_LOGGEDIN;
		}
	pCI_Close( CI_NULL_FLAG, fortezzaInfo->socketIndex );
	}

/* Open a session with the device */

static int initFunction( DEVICE_INFO *deviceInfo, const char *name,
						 const int nameLength )
	{
	FORTEZZA_INFO *fortezzaInfo = deviceInfo->deviceFortezza;
	CI_CONFIG deviceConfiguration;
	CI_TIME cardTime;
	int socket, i, fortezzaStatus, iterationCount = 0;
	int status = CRYPT_ERROR_OPEN;

	UNUSED( name );

	/* The Fortezza open is in theory a bit problematic since with older
	   drivers the open will succeed even if there's no device in the socket, 
	   so after we perform the open we reset the card and check its state to 
	   make sure that we're not just rhapsodising into the void.  This also 
	   catches a bug in the Spyrus driver (see the comment further on) in 
	   which it tries to open a nonexistent device in the USB (pseudo)-slot 
	   before it opens the real Fortezza card in the PCMCIA slot.
	   
	   For some drivers such as the 1996-vintage (non-PnP) NT Fortezza 
	   driver which uses a custom kernel driver to handle PCMCIA cards this 
	   isn't a problem because the driver won't load unless there's a card 
	   inserted, but newer PnP drivers, multi-slot readers with the card 
	   inserted in a slot other than the first one, and the Unix driver 
	   (which has a dedicated daemon to handle the card) may not exhibit 
	   this behaviour so we check for things working in the manner specified 
	   in the docs.

	   The choice of socket for the card can be a bit confusing.  According 
	   to some docs the socket can start from 0 (in violation of the spec),
	   whereas others say they should start from 1, since some drivers do
	   start at slot 0 we go from there (typically we just get a 
	   CI_INV_SOCKET_INDEX for slot 0 if the driver happens to start at 1).  
	   
	   Once we've done that, we reset the card to get it into a known state 
	   (although judging by the equivalent time delay of CI_Open() and 
	   CI_Reset(), the open does this anyway) and check that a card is 
	   actually present (see the comments above - the NSA must be using 
	   their own drivers recovered from crashed UFOs if their ones really do 
	   behave as documented) */
	for( socket = 0; socket <= noSockets && \
					 iterationCount++ < FAILSAFE_ITERATIONS_MED; 
		 socket++ )
		{
		CI_STATE deviceState;

		/* Try and open the card in the current socket */
		fortezzaStatus = pCI_Open( CI_NULL_FLAG, socket );
		if( fortezzaStatus != CI_OK )
			continue;
		fortezzaInfo->socketIndex = socket;

		/* We've opened the card, reset it to get it into a known state
		   and make sure that the state is valid.  Unfortunately the exact 
		   definition of a valid state is a bit tricky, for example we 
		   shouldn't allow the initialised or SSO initialised states here 
		   since there doesn't appear to be any way to get from them to 
		   CAW initialised at this point (that is, you need to go 
		   uninitialised -> initialised -> SSO initialised -> CAW 
		   initialised in a straight sequence), however we need to get
		   past this point in order to perform the only valid operation on
		   the card (zeroise) so we have to let these pass even though
		   there's not much we can do in them */
		fortezzaStatus = pCI_Reset();
		if( fortezzaStatus == CI_NO_CARD )
			/* Some versions of the Syprus driver return CI_NO_CARD at this
			   point if the Spyrus USB (pseudo-)slot is enabled, since they
			   allow an open of the USB pseudo-slot (even though no device
			   is present) and then fail to communicate with the nonexistant
			   device.  If we get this error, we continue, since the 
			   Fortezza should be present in a later slot */
			continue;
		if( fortezzaStatus == CI_OK )
			fortezzaStatus = pCI_GetState( &deviceState );
		if( fortezzaStatus != CI_OK || \
			( deviceState == CI_POWER_UP || \
			  deviceState == CI_INTERNAL_FAILURE ) )
			{
			pCI_Close( CI_NULL_FLAG, socket );
			if( fortezzaStatus == CI_OK )
				fortezzaStatus = CI_INV_STATE;
			continue;
			}
		deviceInfo->flags = DEVICE_ACTIVE | DEVICE_NEEDSLOGIN;
		status = CRYPT_OK;
		break;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();
	if( cryptStatusError( status ) )
		{
		fortezzaInfo->errorCode = fortezzaStatus;
		return( status );
		}

	/* Since the onboard clock could be arbitrarily inaccurate (and even 
	   nonfunctional by now on older cards, since the design life was only
	   7 years), we compare it with the system time and only rely on it if 
	   it's within +/- 1 day of the system time */
	status = pCI_GetTime( cardTime );
	if( status == CI_OK )
		{
		const time_t theTime = getTokenTime( cardTime );
		const time_t currentTime = getTime();

		if( theTime >= currentTime - 86400 && \
			theTime <= currentTime + 86400 )
			deviceInfo->flags |= DEVICE_TIME;
		}

	/* Set up device-specific information.  We can't read the personality 
	   list until the user logs on, so all we can do at this point is 
	   allocate memory for it.  Note that personality 0 can never be selected
	   and so it isn't returned when the personality info is read, this leads 
	   to confusing fencepost errors so when we allocate/read the personality
	   info we leave space for a zero-th personality which is never used */
	pCI_GetConfiguration( &deviceConfiguration );
	fortezzaInfo->largestBlockSize = deviceConfiguration.LargestBlockSize;
	fortezzaInfo->minPinSize = 4;
	fortezzaInfo->maxPinSize = CI_PIN_SIZE;
	fortezzaInfo->keyRegisterCount = deviceConfiguration.KeyRegisterCount;
	fortezzaInfo->keyRegisterFlags = 1;	/* Register 0 is reserved */
	fortezzaInfo->personalityCount = deviceConfiguration.CertificateCount + 1;
	fortezzaInfo->personalities = \
					clAlloc( "initFunction", fortezzaInfo->personalityCount * \
											 sizeof( CI_PERSON ) );
	fortezzaInfo->certHashes = \
					clAlloc( "initFunction", fortezzaInfo->personalityCount * \
											 sizeof( CI_HASHVALUE ) );
	if( fortezzaInfo->personalities == NULL || \
		fortezzaInfo->certHashes == NULL )
		{
		shutdownFunction( deviceInfo );
		return( CRYPT_ERROR_MEMORY );
		}
	memset( fortezzaInfo->personalities, 0, 
			fortezzaInfo->personalityCount * sizeof( CI_PERSON ) );
	fortezzaInfo->currentPersonality = CRYPT_ERROR;
	memset( fortezzaInfo->certHashes, 0, 
			fortezzaInfo->personalityCount * sizeof( CI_HASHVALUE ) );
	fortezzaInfo->certHashesInitialised = FALSE;
	memcpy( fortezzaInfo->labelBuffer, deviceConfiguration.ProductName, 
			CI_NAME_SIZE );
	for( i = CI_NAME_SIZE;
		 i > 0 && ( fortezzaInfo->labelBuffer[ i - 1 ] == ' ' || \
					!fortezzaInfo->labelBuffer[ i - 1 ] ); 
		 i-- );
	fortezzaInfo->labelBuffer[ i ] = '\0';
	deviceInfo->label = fortezzaInfo->labelBuffer;

	return( CRYPT_OK );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_ATTRIBUTE_TYPE type,
							const void *data, const int dataLength )
	{
	FORTEZZA_INFO *fortezzaInfo = deviceInfo->deviceFortezza;
	int status;

	/* Handle user authorisation */
	if( type == CRYPT_DEVINFO_AUTHENT_USER || \
		type == CRYPT_DEVINFO_AUTHENT_SUPERVISOR )
		{
		CI_PERSON *personalityList = fortezzaInfo->personalities;
		CI_PIN pin;
		BYTE ivBuffer[ 64 + 8 ];	/* For LEAF handling */
		int certIndex;

		initPIN( pin, data, dataLength );
		status = pCI_CheckPIN( ( type == CRYPT_DEVINFO_AUTHENT_USER ) ? \
							   CI_USER_PIN : CI_SSO_PIN, pin );
		if( status != CI_OK )
			return( ( status == CI_FAIL ) ? CRYPT_ERROR_WRONGKEY : \
					mapError( status, CRYPT_ERROR_WRONGKEY ) );

		/* Get the list of device personalities (skipping the zero-th 
		   personality, which can't be selected) and lock the device for our 
		   exclusive use.  We should really do this as soon as we open the 
		   device to make sure that the user isn't presented with any nasty 
		   surprises due to state changes caused by other active sessions 
		   with the device, but the driver won't let us do it until we've 
		   authenticated ourselves to the device */
		status = pCI_GetPersonalityList( fortezzaInfo->personalityCount - 1, 
										 &personalityList[ 1 ] );
		if( status == CI_OK )
			{
			int index;

			/* Set a label for the zero-th personality (which can't be 
			   explicitly accessed but whose cert can be read) to make sure 
			   that it isn't treated as an empty personality slot */
			strcpy( personalityList[ 0 ].CertLabel, 
					"PAA1FFFFPersonality 0 dummy label" );

			/* Perform a sanity check for certificate indices.  The 
			   documentation implies that the certificate index always 
			   matches the personality index (skipping the zero-th 
			   personality), but doesn't seem to mandate this anywhere so 
			   we make sure that things really are set up this way */
			for( index = 0; index < fortezzaInfo->personalityCount && \
							index < FAILSAFE_ITERATIONS_MED; index++ )
				{
				CI_PERSON *personality = getPersonality( fortezzaInfo, 
														 index );

				if( personality->CertificateIndex != 0 && \
					personality->CertificateIndex != index )
					{
					status = CI_BAD_TUPLES;
					break;
					}
				}
			if( index >= FAILSAFE_ITERATIONS_MED )
				retIntError();
			}
		if( status == CI_OK )
			status = pCI_Lock( CI_NULL_FLAG );
		if( status != CI_OK )
			{
			pCI_Reset();	/* Log off */
			fortezzaInfo->errorCode = status;
			return( CRYPT_ERROR_FAILED );
			}

		/* Look for the most likely required personality (other than 
		   personality 0, which is a non-personality used for the CA
		   root cert) and set it as the currently active one.  If this 
		   fails we stay with the default personality for lack of any 
		   better way to handle it */
		certIndex = findCertificateFromLabel( fortezzaInfo, NULL, 0 );
		if( !cryptStatusError( certIndex ) && certIndex > 0 )
			{
			pCI_SetPersonality( certIndex );
			fortezzaInfo->currentPersonality = certIndex;
			}

		/* Handle LEAF suppression.  On LEAF-suppressed cards the LEAF bytes
		   are replaced by 'THIS IS NOT LEAF', in case there are cards that
		   use a different string we remember it with the device info so we 
		   can load LEAF-less IV's */
		status = pCI_DeleteKey( 1 );
		if( status == CI_OK )
			status = pCI_GenerateMEK( 1, 0 );
		if( status == CI_OK )
			status = pCI_SetKey( 1 );
		if( status == CI_OK )
			status = pCI_GenerateIV( ivBuffer );
		memcpy( fortezzaInfo->leafString, ( status == CI_OK ) ? \
				ivBuffer : "THIS IS NOT LEAF", 16 );
		pCI_DeleteKey( 1 );

		/* The device is now ready for use */
		deviceInfo->flags |= DEVICE_LOGGEDIN;		
		krnlSendMessage( deviceInfo->objectHandle, IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );
		return( CRYPT_OK );
		}

	/* Handle authorisation value change.  Fortezza uses a multi-stage
	   bootstrap FSM and requires that all of the various intialisation 
	   functions be used one after the other, with no intervening operations 
	   apart from setting the PAA (CA root) cert in the SSO initialised 
	   state.  Interrupting the process (for example by logging off/closing 
	   the device) requires that it be restarted from scratch:

			   uninitialised
					v
				CI_Zeroize			(enter zeroise PIN)
					v
				 zeroised
					v
				CI_CheckPIN			(enter init PIN)
					v
				initialised
					v
				CI_ChangePIN		(set SSO PIN)
					v
			  SSO initialised
					v
				CI_ChangePIN		(set user PIN)
					v
			  user initialised

	   The single-sequence requirement means that the initialised -> SSO
	   initialised step re-uses the PIN set at initialisation, and the SSO
	   initialised -> user initialised uses the same PIN as the old and new
	   PIN, since there's no user PIN set at that point.  Once we've set the
	   initial user PIN, the card is automagically moved into the user
	   initialised state */
	if( type == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR )
		{
		CI_PIN oldPIN, newPIN;

		/* Make sure that there's an SSO PIN present from a previous device
		   initialisation */
		if( strlen( fortezzaInfo->initPIN ) <= 0 )
			{
			setErrorInfo( deviceInfo, CRYPT_DEVINFO_INITIALISE, 
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}

		/* This assumes that we're in the initialised state and are setting 
		   the initial SSO PIN to move us into the SSO initialised state, 
		   for which oldPIN == initialisation PIN.  Once we've done this we
		   clear the initialisation PIN, since it's no longer valid in the 
		   new state */
		initPIN( oldPIN, fortezzaInfo->initPIN, 
				 strlen( fortezzaInfo->initPIN ) );
		initPIN( newPIN, data, dataLength );
		status = pCI_ChangePIN( CI_SSO_PIN, oldPIN, newPIN );
		zeroise( fortezzaInfo->initPIN, CRYPT_MAX_TEXTSIZE );
		return( ( status == CI_FAIL ) ? CRYPT_ERROR_WRONGKEY : \
				mapError( status, CRYPT_ERROR_WRONGKEY ) );
		}
	if( type == CRYPT_DEVINFO_SET_AUTHENT_USER )
		{
		CI_PIN oldPIN, newPIN;

		/* This assumes that we're in the SSO initialised state and are 
		   setting the initial user PIN to move us into the user initialised
		   state, for which oldPIN == newPIN */
		initPIN( oldPIN, data, dataLength );
		initPIN( newPIN, data, dataLength );
		status = pCI_ChangePIN( CI_USER_PIN, oldPIN, newPIN );
		return( ( status == CI_FAIL ) ? CRYPT_ERROR_WRONGKEY : \
				mapError( status, CRYPT_ERROR_WRONGKEY ) );
		}

	/* Handle initialisation */
	if( type == CRYPT_DEVINFO_INITIALISE )
		{
		CI_RANDOM randomBuffer;
		CI_STATE deviceState;
		CI_PIN pin;

		/* Make sure that the device is in the uninitialised state */
		status = pCI_GetState( &deviceState );
		if( status != CI_OK || deviceState != CI_UNINITIALIZED )
			return( CRYPT_ERROR_INITED );

		/* Log on with the SSO PIN */
		initPIN( pin, data, dataLength );
		status = pCI_CheckPIN( CI_SSO_PIN, pin );
		if( status != CI_OK )
			return( mapError( status, CRYPT_ERROR_FAILED ) );

		/* Load the random number seed and storage key from the device's
		   RNG output and make sure that the card has now in the 
		   initialised state */
		status = pCI_GenerateRandom( randomBuffer );
		if( status == CI_OK )
			status = pCI_LoadInitValues( randomBuffer, 
										 randomBuffer + sizeof( CI_RANDSEED ) );
		zeroise( randomBuffer, sizeof( CI_RANDOM ) );
		if( status == CI_OK )
			status = pCI_GetState( &deviceState );
		if( status != CI_OK )
			return( mapError( status, CRYPT_ERROR_FAILED ) );
		if( deviceState != CI_INITIALIZED )
			return( CRYPT_ERROR_FAILED );

		/* Remember the initialisation PIN for a future CI_ChangePIN() */
		memcpy( fortezzaInfo->initPIN, data, dataLength );
		fortezzaInfo->initPIN[ dataLength ] = '\0';

		return( CRYPT_OK );
		}

	/* Handle zeroisation */
	if( type == CRYPT_DEVINFO_ZEROISE )
		{
		CI_STATE deviceState;
		CI_PIN pin;

		/* Zeroise the card */
		status = pCI_Zeroize();
		if( status == CI_OK )
			status = pCI_GetState( &deviceState );
		if( status != CI_OK )
			return( mapError( status, CRYPT_ERROR_FAILED ) );
		if( deviceState != CI_ZEROIZED )
			return( CRYPT_ERROR_FAILED );

		/* Clear any in-memory state information that we were holding about 
		   the card */
		memset( fortezzaInfo->personalities, 0, 
				fortezzaInfo->personalityCount * sizeof( CI_PERSON ) );
		memset( fortezzaInfo->certHashes, 0, 
				fortezzaInfo->personalityCount * sizeof( CI_HASHVALUE ) );
		fortezzaInfo->certHashesInitialised = FALSE;
		fortezzaInfo->currentPersonality = CRYPT_ERROR;

		/* Log on with the zeroise PIN to move it into the uninitialised 
		   state */
		initPIN( pin, data, dataLength );
		status = pCI_CheckPIN( CI_SSO_PIN, pin );
		return( mapError( status, CRYPT_ERROR_WRONGKEY ) );
		}

	/* Handle high-reliability time */
	if( type == CRYPT_IATTRIBUTE_TIME )
		{
		CI_TIME cardTime;
		time_t *timePtr = ( time_t * ) data, theTime;

		status = pCI_GetTime( cardTime );
		if( status != CI_OK )
			return( mapError( status, CRYPT_ERROR_FAILED ) );
		if( ( theTime = getTokenTime( cardTime ) ) <= MIN_TIME_VALUE )
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
	CI_RANDOM randomBuffer;
	BYTE *bufPtr = buffer;
	int count, status;

	/* Get as many 20-byte blocks as required to fill the request */
	for( count = 0; count < length; count += 20 )
		{
		const int noBytes = min( 20, length - count );

		status = pCI_GenerateRandom( randomBuffer );
		if( status != CI_OK )
			break;
	
		memcpy( bufPtr, randomBuffer, noBytes );
		bufPtr += noBytes;
		}
	zeroise( randomBuffer, 20 );

	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

/* Instantiate an object in a device.  This works like the create context
   function but instantiates a cryptlib object using data already contained
   in the device (for example a stored private key or certificate).  If the
   value being read is a public key and there's a certificate attached, the
   instantiated object is a native cryptlib object rather than a device
   object with a native certificate object attached because there doesn't 
   appear to be any good reason to create the public-key object in the device, 
   and the cryptlib native object will probably be faster anyway */

static int getItemFunction( DEVICE_INFO *deviceInfo,
							CRYPT_CONTEXT *iCryptContext,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID, const int keyIDlength,
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	CRYPT_CERTIFICATE iCryptCert;
	CRYPT_ALGO_TYPE cryptAlgo;
	static const int keySize = 128;
	const CAPABILITY_INFO *capabilityInfoPtr;
	FORTEZZA_INFO *fortezzaInfo = deviceInfo->deviceFortezza;
	CI_PERSON *personality;
	CI_CERTIFICATE certificate;
	MESSAGE_DATA msgData;
	BOOLEAN certPresent = TRUE;
	int certIndex, status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME );

	/* Find the referenced personality on the device and determine the 
	   algorithm type for the key */
	certIndex = findCertificateFromLabel( fortezzaInfo, keyID, keyIDlength );
	if( certIndex == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		/* If we're just checking whether an object exists, return now */
		return( CRYPT_OK );
	personality = getPersonality( fortezzaInfo, certIndex );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		{
		/* All we want is the key label, copy it back to the caller and
		   exit */
		*auxInfoLength = strlen( personality->CertLabel + 8 );
		if( auxInfo != NULL )
			memcpy( auxInfo, personality->CertLabel + 8, *auxInfoLength );
		return( CRYPT_OK );
		}
	status = pCI_GetCertificate( certIndex, certificate );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_READ ) );
	if( !memcmp( personality->CertLabel, "TEMP", 4 ) )
		{
		STREAM stream;

		/* It's a work in progress, read the algorithm from the start of the 
		   public key data */
		sMemConnect( &stream, certificate, 128 );
		status = readSequence( &stream, NULL );
		if( !cryptStatusError( status ) )
			status = readAlgoID( &stream, &cryptAlgo );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		/* Remember that there's no cert available for this key */
		certPresent = FALSE;
		}
	else
		/* It's a certificate, determine the algorithm type from the label */
		if( !memcmp( personality->CertLabel, "DSA", 3 ) || \
			!memcmp( personality->CertLabel, "CAX", 3 ) || \
			!memcmp( personality->CertLabel, "PCA", 3 ) || \
			!memcmp( personality->CertLabel, "PAA", 3 ) )
			cryptAlgo = CRYPT_ALGO_DSA;
		else
			if( !memcmp( personality->CertLabel, "KEA", 3 ) )
				cryptAlgo = CRYPT_ALGO_KEA;
			else
				return( CRYPT_ERROR_BADDATA );
	capabilityInfoPtr = findCapabilityInfo( deviceInfo->capabilityInfoList, 
											cryptAlgo );
	if( capabilityInfoPtr == NULL )
		return( CRYPT_ERROR_NOTAVAIL );
	
	/* If we're after a private key, make sure that it really is a private 
	   key.  This check isn't completely effective since the CA labels 
	   don't identify the presence of a private key */
	if( personality->CertLabel[ 4 ] == 'X' && \
		itemType == KEYMGMT_ITEM_PRIVATEKEY )
		return( CRYPT_ERROR_NOTFOUND );

	/* Try and create a certificate chain that matches the key.  The process 
	   is as follows:

		if public key
			if cert
				create native cert chain (+key) object
			else
				create device pubkey object, mark as "key loaded"
		else
			create device privkey object, mark as "key loaded"
			if cert
				create native data-only cert chain object
				attach cert chain object to key

	   The reason for doing things this way is given in the comment at the 
	   top of this section */
	if( certPresent )
		{
		status = iCryptImportCertIndirect( &iCryptCert, 
						deviceInfo->objectHandle, keyIDtype, keyID, 
						keyIDlength, ( itemType == KEYMGMT_ITEM_PRIVATEKEY ) ? \
						KEYMGMT_FLAG_DATAONLY_CERT : 0 );
		if( cryptStatusError( status ) )
			return( status );

		/* We got the cert, if we're being asked for a public key then we've 
		   created a native object to contain it so we return that */
		if( itemType == KEYMGMT_ITEM_PUBLICKEY )
			{
			/* Set up the keying info in the context based on the data from
			   the cert if necessary */
			if( cryptAlgo == CRYPT_ALGO_KEA )
				{
				BYTE keyDataBuffer[ 1024 + 8 ];

				setMessageData( &msgData, keyDataBuffer, 1024 );
				status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
										  &msgData, CRYPT_IATTRIBUTE_SPKI );
				if( cryptStatusOK( status ) )
					status = krnlSendMessage( iCryptCert, 
											  IMESSAGE_SETATTRIBUTE_S, 
											  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
				if( cryptStatusError( status ) )
					{
					krnlSendNotifier( iCryptCert, IMESSAGE_DECREFCOUNT );
					return( status );
					}
				}

			*iCryptContext = iCryptCert;
			return( CRYPT_OK );
			}
		}

	/* Create a dummy context for the key, remember the device it's 
	   contained in, the index of the device-internal key, and the object's 
	   label, mark it as initialised (i.e. with a key loaded), and if 
	   there's a cert present attach it to the context.  The cert is an 
	   internal object used only by the context so we tell the kernel to 
	   mark it as owned by the context only */
	status = createContextFromCapability( iCryptContext, deviceInfo->ownerHandle,
										  capabilityInfoPtr, 
										  CREATEOBJECT_FLAG_DUMMY );
	if( cryptStatusError( status ) )
		{
		if( certPresent )
			krnlSendNotifier( iCryptCert, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	krnlSendMessage( *iCryptContext, IMESSAGE_SETDEPENDENT,
					 &deviceInfo->objectHandle, SETDEP_OPTION_INCREF );
	krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE, &certIndex, 
					 CRYPT_IATTRIBUTE_DEVICEOBJECT );
	setMessageData( &msgData, personality->CertLabel + 8,
					 min( strlen( personality->CertLabel + 8 ),
						  CRYPT_MAX_TEXTSIZE ) );
	krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_LABEL );
	krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &keySize, CRYPT_IATTRIBUTE_KEYSIZE );
	if( certPresent && cryptAlgo == CRYPT_ALGO_KEA )
		{
		BYTE keyDataBuffer[ 1024 + 8 ];

		/* Set up the keying info in the context based on the data from the 
		   cert if necessary */
		setMessageData( &msgData, keyDataBuffer, 1024 );
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_SPKI );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
									  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( *iCryptContext, IMESSAGE_DECREFCOUNT );
			*iCryptContext = CRYPT_ERROR;
			return( status );
			}
		}
	else
		/* If we don't set keying the info, we have to manually move the 
		   context into the initialised state */
		krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );
	if( certPresent )
		krnlSendMessage( *iCryptContext, IMESSAGE_SETDEPENDENT, &iCryptCert, 
						 SETDEP_OPTION_NOINCREF );

	return( status );
	}

/* Update a device with a certificate */

static int setItemFunction( DEVICE_INFO *deviceInfo, 
							const CRYPT_HANDLE iCryptHandle )
	{
	CRYPT_CERTIFICATE iCryptCert;
	FORTEZZA_INFO *fortezzaInfo = deviceInfo->deviceFortezza;
	int status;

	/* Get the cert object's handle, lock it for our exclusive use, update 
	   the card with the cert(s), and unlock it to allow others access */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETDEPENDENT, 
							  &iCryptCert, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_TRUE, 
								  CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	status = updateCertChain( fortezzaInfo, iCryptCert );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );

	return( status );
	}

/* Delete an object in a device */

static int deleteItemFunction( DEVICE_INFO *deviceInfo,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	FORTEZZA_INFO *fortezzaInfo = deviceInfo->deviceFortezza;
	int certIndex, status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME );

	/* Find the item to delete based on the label */
	certIndex = findCertificateFromLabel( fortezzaInfo, keyID, keyIDlength );
	if( certIndex == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );
	status = pCI_DeleteCertificate( certIndex );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_WRITE ) );
	updateCertificateInfo( fortezzaInfo, certIndex, NULL, 0, "" );
	return( CRYPT_OK );
	}

/* Get the sequence of certs in a chain from a device */

static int getFirstItemFunction( DEVICE_INFO *deviceInfo, 
								 CRYPT_CERTIFICATE *iCertificate,
								 int *stateInfo, 
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength,
								 const KEYMGMT_ITEM_TYPE itemType, 
								 const int options )
	{
	FORTEZZA_INFO *fortezzaInfo = deviceInfo->deviceFortezza;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE buffer[ CI_CERT_SIZE + 8 ];
	int status;

	assert( keyIDtype == CRYPT_KEYID_NAME && keyID != NULL );
	assert( stateInfo != NULL );

	/* Find the cert based on the label */
	*stateInfo = findCertificateFromLabel( fortezzaInfo, keyID, 
										   keyIDlength );
	if( *stateInfo == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Get the cert at this position */
	status = pCI_GetCertificate( *stateInfo, buffer );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_READ ) );
	setMessageCreateObjectIndirectInfo( &createInfo, buffer, CI_CERT_SIZE,
										CRYPT_CERTTYPE_CERTIFICATE );
	createInfo.arg1 = ( options & KEYMGMT_FLAG_DATAONLY_CERT ) ? \
					  CERTFORMAT_DATAONLY : CRYPT_CERTTYPE_CERTIFICATE;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		*iCertificate = createInfo.cryptHandle;
	return( status );
	}

static int getNextItemFunction( DEVICE_INFO *deviceInfo, 
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo, const int options )
	{
	FORTEZZA_INFO *fortezzaInfo = deviceInfo->deviceFortezza;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	CI_PERSON *personality;
	BYTE buffer[ CI_CERT_SIZE + 8 ];
	int status;

	assert( stateInfo != NULL );
	assert( ( *stateInfo >= 0 && *stateInfo < fortezzaInfo->personalityCount ) || \
			*stateInfo == CRYPT_ERROR );

	/* If the previous cert was the last one, there's nothing left to fetch */
	if( *stateInfo == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Find the parent for the last cert that we got using the SDN.605 
	   labelling scheme */
	personality = getPersonality( fortezzaInfo, *stateInfo );
	if( !memcmp( personality->CertLabel + 4, "0999", 4 ) || \
		!memcmp( personality->CertLabel + 6, "FF", 2 ) || \
		sscanf( personality->CertLabel + 6, "%02X", stateInfo ) != 1 )
		*stateInfo = 255;
	if( *stateInfo == 255 )
		{
		*stateInfo = CRYPT_ERROR;
		return( CRYPT_ERROR_NOTFOUND );
		}

	/* Get the cert at this position */
	status = pCI_GetCertificate( *stateInfo, buffer );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_READ ) );
	setMessageCreateObjectIndirectInfo( &createInfo, buffer, CI_CERT_SIZE,
										CRYPT_CERTTYPE_CERTIFICATE );
	createInfo.arg1 = ( options & KEYMGMT_FLAG_DATAONLY_CERT ) ? \
					  CERTFORMAT_DATAONLY : CRYPT_CERTTYPE_CERTIFICATE;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		*iCertificate = createInfo.cryptHandle;
	return( status );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

#if 0

/* Initialise the encryption */

static int initCryptFunction( CONTEXT_INFO *contextInfoPtr )
	{
	int status;

	/* Initially we default to CBC mode */
	assert( contextInfoPtr->ctxConv->mode == CRYPT_MODE_CBC );
	status = pCI_SetMode( CI_DECRYPT_TYPE, CI_CBC64_MODE );
	if( status == CI_OK )
		status = pCI_SetMode( CI_ENCRYPT_TYPE, CI_CBC64_MODE );
	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}
#endif /* 0 */

/* Load an IV.  Handling IV generation/loading is very problematic since we 
   can't generate an IV until the key is generated (since it depends on the 
   key), however implicitly generating a key into the context at this point 
   will change its state so that a future attempt to explicitly generate a key 
   will fail.  This is complicated by the fact that although there are a 
   number of key registers, the cryptologic can only have one active mode and
   one active IV.  To get around this we'd have to do the following:

	initIV:
		if( !key )
			generateKey();
			autoKey = TRUE;
		generateIV();
	
	initKey:
		if( autoKey == TRUE )
			return( OK );
		generateKey()

   but this doesn't work due to the problem mentioned above, so for now we
   just assume we'll be called from within cryptlib, which gets it right (it's
   unlikely that users will be able to work with the complex Fortezza key 
   management, so there's little chance the sequencing will become messed up).
   
   In practice it's even worse than this, because the cryptologic on some 
   cards imposes even more limitations than this.  The standard way to use a
   session/content-enryption key is:

	generate session/conetent-encryption key;
	export wrapped key;
	encrypt data with key;

   This doesn't work here because the act of exporting the session key screws
   up the state of the key.  Specifically, after executing the following code
   sequence:

	// Generate the session key
	CI_DeleteKey( mekIndex );
	CI_GenerateMEK( mekIndex, 0 );
	CI_SetKey( mekIndex );
	CI_GenerateIV( ivBuffer );

	// Export the encrypted session key
	CI_SetPersonality( personality );
	CI_GenerateRa( Ra );
	CI_GenerateTEK( CI_INITIATOR_FLAG, tekIndex, Ra, 
					( void * ) Rb, sizeof( CI_RB ), recipientPublicValue );
	CI_WrapKey( tekIndex, mekIndex, wrappedKey );
	CI_DeleteKey( tekIndex );

	// Encrypt data with the key
	CI_Encrypt( length, buffer, buffer );

   the CI_Encrypt() fails with CI_NO_KEY.  Calling CI_SetKey() before 
   CI_Encrypt() causes it to fail with a CI_NO_IV instead.  Calling 
   CI_Encrypt() immediately after CI_GenerateTEK() results in a CI_FAIL.
   This indicates that the TEK wrapping upsets the state of the cryptologic
   which in turn upsets any attempt to use the MEK later on.

   Because of this problem, we can't generate the IV in the initIVFunction()
   but have to wait until after the key wrap operations have been performed.  
   The code kludges this by setting the ivSet flag at this point without
   setting the IV and then generating the real IV as a side-effect of the key
   wrapping.  This only works if we're wrapping the key for a single recipient 
   using a TEK, it doesn't work if we're wrapping using Ks or if there's more
   than one recipient because we can't tell in advance whether this is the 
   last operation before we encrypt (and therefore whether it's safe to 
   generate an IV now).
   
   The problems with IV handling extend even further than this.  The 
   following simple sequence of calls (generating an IV, reading it out, 
   loading it back in, and then attempting to encrypt) produce a "no IV 
   loaded" error even though all the previous calls succeeded:

	CI_SetMode( CI_DECRYPT_TYPE, CI_CBC64_MODE );
	CI_DeleteKey( 5 );
	CI_GenerateMEK( 5, 0 );
	CI_SetKey( 5 );
	CI_GenerateIV( ivBuffer );
	CI_SetKey( 5 );		// Required or the IV load fails with CI_EXEC_FAIL
	CI_LoadIV( ivBuffer );
	CI_Encrypt( 8, ivBuffer, ivBuffer ); // Result = CI_NO_IV

   Presumably this is because of interlocks on the card or Capstone chip 
   that date back to the LEAF period and which ensure that it's not possible
   to fiddle with non-LEAF'd IV's or anything else even if the card firmware 
   is somehow compromised or has unexpected failure modes.  The result is 
   that it's possible to use the device exactly as intended by its original 
   designers but probably not possible (or at least very difficult) to use it 
   in any other way.  The unexpected return codes are <wild speculation> 
   possibly caused by this functionality not being anticipated by the 
   firmware vendors</wild speculation>.  In any case it's a nice failsafe
   design */

static int initKeyParamsFunction( CONTEXT_INFO *contextInfoPtr, const void *iv,
								  const int ivLength, 
								  const CRYPT_MODE_TYPE mode )
	{
	BYTE ivBuffer[ FORTEZZA_IVSIZE + 8 ];
	int status;

	assert( iv != NULL || mode != CRYPT_MODE_NONE );
	assert( ivLength == CRYPT_USE_DEFAULT || ivLength == 8 );

	/* If there's a mode specified, set the mode for future en/decryption */
	if( mode != CRYPT_MODE_NONE )
		{
		int fortezzaMode;
				
		switch( mode )
			{
			case CRYPT_MODE_ECB:
				fortezzaMode = CI_ECB64_MODE;
				break;

			case CRYPT_MODE_CBC:
				fortezzaMode = CI_CBC64_MODE;
				break;

			case CRYPT_MODE_CFB:
				fortezzaMode = CI_CFB64_MODE;
				break;

			case CRYPT_MODE_OFB:
				fortezzaMode = CI_OFB64_MODE;
				break;
			}
		status = pCI_SetMode( CI_DECRYPT_TYPE, fortezzaMode );
		if( status == CI_OK )
			status = pCI_SetMode( CI_ENCRYPT_TYPE, fortezzaMode );
		if( cryptStatusError( status ) )
			return( mapError( status, CRYPT_ERROR_FAILED ) );
		}

	/* If we were just setting the mode, we're done */
	if( iv == NULL )
		return( CRYPT_OK );

	/* If the user has supplied an IV, load it into the device, taking into
	   account LEAF suppression */
	if( ivLength != CRYPT_USE_DEFAULT )
		{
		if( !( contextInfoPtr->flags & CONTEXT_IV_SET ) )
			{
			CRYPT_DEVICE iCryptDevice;
			DEVICE_INFO *deviceInfo;

			/* Get the LEAF-suppression string from the device associated 
			   with the context */
			status = krnlSendMessage( contextInfoPtr->objectHandle, 
									  IMESSAGE_GETDEPENDENT, &iCryptDevice, 
									  OBJECT_TYPE_DEVICE );
			if( cryptStatusError( status ) )
				return( status );
			status = krnlAcquireObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
										( void ** ) &deviceInfo, 
										CRYPT_ERROR_SIGNALLED );
			if( cryptStatusError( status ) )
				return( status );
			memcpy( ivBuffer, deviceInfo->deviceFortezza->leafString, 16 );
			krnlReleaseObject( deviceInfo->objectHandle );

			/* Copy in the actual IV and load it */
			memcpy( ivBuffer + FORTEZZA_IVSIZE - 8, iv, 8 );
			status = pCI_LoadIV( ivBuffer );
			if( status != CI_OK )
				return( mapError( status, CRYPT_ERROR_FAILED ) );
			}

		/* Copy the IV details into the context */
		contextInfoPtr->ctxConv->ivLength = 8;
		memset( contextInfoPtr->ctxConv->iv, 0, CRYPT_MAX_IVSIZE );
		memcpy( contextInfoPtr->ctxConv->iv, iv, 8 );
		contextInfoPtr->flags |= CONTEXT_IV_SET;

		return( CRYPT_OK );
		}

	/* We can't generate an IV at this point (see the comment above) so all
	   we can do is set up a dummy IV and set the 'IV set' flag to avoid 
	   getting an error from the higher-level code and return.  The real IV 
	   will be set when the key is wrapped */
	memset( contextInfoPtr->ctxConv->iv, 0, CRYPT_MAX_IVSIZE );
	contextInfoPtr->ctxConv->ivLength = 8;
	contextInfoPtr->flags |= CONTEXT_IV_SET;

	return( CRYPT_OK );
	}

/* Initialise a key.  Since Fortezza keys can't be directly loaded, this
   function always returns a permission denied error */

static int initKeyFunction( CONTEXT_INFO *contextInfoPtr, const void *key, 
							const int keyLength )
	{
	UNUSED( contextInfoPtr );
	UNUSED( key );

	return( CRYPT_ERROR_PERMISSION );
	}

/* Generate a key.  This is somewhat ugly since Fortezza keys (at least KEA 
   ones) require the use of shared domain parameters (the DSA p, q, and g 
   values) that are managed through some sort of unspecified external means.
   At the moment we use the domain parameters from a Motorola test 
   implementation, users in other domains will have to substitute their own 
   parameters as required */

static int generateKeyFunction( CONTEXT_INFO *contextInfoPtr,
								const int keySizeBits )
	{
	static const CI_P p = {
		0xD4, 0x38, 0x02, 0xC5, 0x35, 0x7B, 0xD5, 0x0B, 
		0xA1, 0x7E, 0x5D, 0x72, 0x59, 0x63, 0x55, 0xD3,
		0x45, 0x56, 0xEA, 0xE2, 0x25, 0x1A, 0x6B, 0xC5, 
		0xA4, 0xAB, 0xAA, 0x0B, 0xD4, 0x62, 0xB4, 0xD2, 
		0x21, 0xB1, 0x95, 0xA2, 0xC6, 0x01, 0xC9, 0xC3, 
		0xFA, 0x01, 0x6F, 0x79, 0x86, 0x83, 0x3D, 0x03, 
		0x61, 0xE1, 0xF1, 0x92, 0xAC, 0xBC, 0x03, 0x4E, 
		0x89, 0xA3, 0xC9, 0x53, 0x4A, 0xF7, 0xE2, 0xA6, 
		0x48, 0xCF, 0x42, 0x1E, 0x21, 0xB1, 0x5C, 0x2B, 
		0x3A, 0x7F, 0xBA, 0xBE, 0x6B, 0x5A, 0xF7, 0x0A, 
		0x26, 0xD8, 0x8E, 0x1B, 0xEB, 0xEC, 0xBF, 0x1E, 
		0x5A, 0x3F, 0x45, 0xC0, 0xBD, 0x31, 0x23, 0xBE, 
		0x69, 0x71, 0xA7, 0xC2, 0x90, 0xFE, 0xA5, 0xD6, 
		0x80, 0xB5, 0x24, 0xDC, 0x44, 0x9C, 0xEB, 0x4D, 
		0xF9, 0xDA, 0xF0, 0xC8, 0xE8, 0xA2, 0x4C, 0x99, 
		0x07, 0x5C, 0x8E, 0x35, 0x2B, 0x7D, 0x57, 0x8D
		};
	static const CI_Q q = {
		0xA7, 0x83, 0x9B, 0xF3, 0xBD, 0x2C, 0x20, 0x07, 
		0xFC, 0x4C, 0xE7, 0xE8, 0x9F, 0xF3, 0x39, 0x83, 
		0x51, 0x0D, 0xDC, 0xDD
		};
	static const CI_G g = {
		0x0E, 0x3B, 0x46, 0x31, 0x8A, 0x0A, 0x58, 0x86, 
		0x40, 0x84, 0xE3, 0xA1, 0x22, 0x0D, 0x88, 0xCA, 
		0x90, 0x88, 0x57, 0x64, 0x9F, 0x01, 0x21, 0xE0, 
		0x15, 0x05, 0x94, 0x24, 0x82, 0xE2, 0x10, 0x90, 
		0xD9, 0xE1, 0x4E, 0x10, 0x5C, 0xE7, 0x54, 0x6B, 
		0xD4, 0x0C, 0x2B, 0x1B, 0x59, 0x0A, 0xA0, 0xB5, 
		0xA1, 0x7D, 0xB5, 0x07, 0xE3, 0x65, 0x7C, 0xEA, 
		0x90, 0xD8, 0x8E, 0x30, 0x42, 0xE4, 0x85, 0xBB, 
		0xAC, 0xFA, 0x4E, 0x76, 0x4B, 0x78, 0x0E, 0xDF, 
		0x6C, 0xE5, 0xA6, 0xE1, 0xBD, 0x59, 0x77, 0x7D, 
		0xA6, 0x97, 0x59, 0xC5, 0x29, 0xA7, 0xB3, 0x3F, 
		0x95, 0x3E, 0x9D, 0xF1, 0x59, 0x2D, 0xF7, 0x42, 
		0x87, 0x62, 0x3F, 0xF1, 0xB8, 0x6F, 0xC7, 0x3D, 
		0x4B, 0xB8, 0x8D, 0x74, 0xC4, 0xCA, 0x44, 0x90, 
		0xCF, 0x67, 0xDB, 0xDE, 0x14, 0x60, 0x97, 0x4A, 
		0xD1, 0xF7, 0x6D, 0x9E, 0x09, 0x94, 0xC4, 0x0D
		};
	const CRYPT_ALGO_TYPE cryptAlgo = contextInfoPtr->capabilityInfo->cryptAlgo;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	FORTEZZA_INFO *fortezzaInfo;
	BYTE yBuffer[ 128 + 8 ], keyDataBuffer[ 1024 + 8 ];
	int certIndex, keyDataSize, status;

	assert( keySizeBits == 80 || keySizeBits == bytesToBits( 128 ) );

	/* Get the info for the device associated with this context */
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlAcquireObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( void ** ) &deviceInfo, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	fortezzaInfo = deviceInfo->deviceFortezza;

	/* If it's a Skipjack context, just generate a key in the key register */
	if( cryptAlgo == CRYPT_ALGO_SKIPJACK )
		{
		const int keyIndex = findFreeKeyRegister( fortezzaInfo );

		if( cryptStatusError( keyIndex ) )
			{
			krnlReleaseObject( deviceInfo->objectHandle );
			return( keyIndex );
			}

		/* We've got a key register to use, generate a key into it and 
		   remember its value */
		status = pCI_GenerateMEK( keyIndex, 0 );
		if( status == CI_OK )
			{
			const int keySize = bitsToBytes( 80 );

			/* Mark this key register as being in use */
			fortezzaInfo->keyRegisterFlags |= ( 1 << keyIndex );

			/* Remember what we've set up */
			krnlSendMessage( contextInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE, ( void * ) &keyIndex, 
							 CRYPT_IATTRIBUTE_DEVICEOBJECT );
			krnlSendMessage( contextInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE,  ( void * ) &keySize, 
							 CRYPT_IATTRIBUTE_KEYSIZE );
			}
		status = mapError( status, CRYPT_ERROR_FAILED );

		krnlReleaseObject( deviceInfo->objectHandle );
		return( status );
		}

	/* It's a DSA or KEA context, find a certificate slot in which we can 
	   store the new key */
	certIndex = findFreeCertificate( fortezzaInfo );
	if( certIndex == CRYPT_ERROR )
		{
		krnlReleaseObject( deviceInfo->objectHandle );
		return( CRYPT_ERROR_OVERFLOW );
		}

#ifndef NO_UPDATE
	/* Generate the X component, receiving the Y component in return */
	status = pCI_GenerateX( certIndex, ( cryptAlgo == CRYPT_ALGO_DSA ) ? \
							CI_DSA_TYPE : CI_KEA_TYPE, 128, 20, ( void * ) p, 
							( void * ) q, ( void * ) g, 128, yBuffer );
	if( status != CI_OK )
		{
		status = mapError( status, CRYPT_ERROR_FAILED );
		krnlReleaseObject( deviceInfo->objectHandle );
		return( status );
		}
#else
	memset( yBuffer, 0, 128 );
	memcpy( yBuffer, "\x12\x34\x56\x78\x90\x12\x34\x56", 8 );
	memcpy( yBuffer + 120, "\x12\x34\x56\x78\x90\x12\x34\x56", 8 );
#endif /* NO_UPDATE */

	/* Send the keying info to the context.  We send the keying info as
	   CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL rather than 
	   CRYPT_IATTRIBUTE_KEY_SPKI since the latter transitions the context 
	   into the high state.  We don't want to do this because we're already 
	   in the middle of processing a message that does this on completion, 
	   all we're doing here is sending in encoded public key data for use by 
	   objects such as certificates */
	krnlSendMessage( contextInfoPtr->objectHandle, IMESSAGE_SETATTRIBUTE, 
					 ( void * ) &keySizeBits, CRYPT_IATTRIBUTE_KEYSIZE );
	status = keyDataSize = writeFlatPublicKey( NULL, 0, cryptAlgo, p, 128, 
											   q, 20, g, 128, yBuffer, 128 );
	if( !cryptStatusError( status ) )
		status = writeFlatPublicKey( keyDataBuffer, 1024, cryptAlgo, 
									 p, 128, q, 20, g, 128, yBuffer, 128 );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, keyDataBuffer, keyDataSize );
		status = krnlSendMessage( contextInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL );
		}
	if( cryptStatusError( status ) )
		{
#ifndef NO_UPDATE
		pCI_DeleteCertificate( certIndex );
#endif /* NO_UPDATE */
		krnlReleaseObject( deviceInfo->objectHandle );
		return( status );
		}

	/* Save the encoded public key info in the card.  We need to do this 
	   because we can't recreate the y value without generating a new private
	   key */
	status = updateRawKey( fortezzaInfo, certIndex, keyDataBuffer, 
						   keyDataSize, contextInfoPtr->label );
	if( cryptStatusError( status ) )
		{
#ifndef NO_UPDATE
		pCI_DeleteCertificate( certIndex );
#endif /* NO_UPDATE */
		krnlReleaseObject( deviceInfo->objectHandle );
		return( status );
		}

	/* Remember what we've set up */
	krnlSendMessage( contextInfoPtr->objectHandle, IMESSAGE_SETATTRIBUTE,
					 &certIndex, CRYPT_IATTRIBUTE_DEVICEOBJECT );
	contextInfoPtr->flags &= ~CONTEXT_ISPUBLICKEY;

	krnlReleaseObject( deviceInfo->objectHandle );
	return( status );
	}

/* Select the appropriate personality for a context if required.  There are
   two variations, one that selects a personality given context data and one 
   that selects it given device data */

static int selectPersonalityContext( const CONTEXT_INFO *contextInfoPtr )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	FORTEZZA_INFO *fortezzaInfo;
	int status;

	assert( contextInfoPtr->deviceObject > 0 );

	status = krnlSendMessage( contextInfoPtr->objectHandle, IMESSAGE_GETDEPENDENT, 
							  &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlAcquireObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( void ** ) &deviceInfo, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	fortezzaInfo = deviceInfo->deviceFortezza;
	if( fortezzaInfo->currentPersonality != contextInfoPtr->deviceObject )
		{
		status = pCI_SetPersonality( contextInfoPtr->deviceObject );
		if( status == CI_OK )
			fortezzaInfo->currentPersonality = contextInfoPtr->deviceObject;
		}
	krnlReleaseObject( deviceInfo->objectHandle );
	return( status );
	}

static int selectPersonality( DEVICE_INFO *deviceInfo, 
							  const CRYPT_CONTEXT iCryptContext )
	{
	FORTEZZA_INFO *fortezzaInfo = deviceInfo->deviceFortezza;
	int deviceObject, status;

	/* Get the personality associated with the context */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, 
							  &deviceObject, CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusError( status ) )
		return( status );
	assert( deviceObject > 0 );

	/* If it's not the currently selected one, select it */
	if( fortezzaInfo->currentPersonality != deviceObject )
		{
		status = pCI_SetPersonality( deviceObject );
		if( status == CI_OK )
			fortezzaInfo->currentPersonality = deviceObject;
		}

	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

/* Encrypt/decrypt data */

static int encryptFunction( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							int length )
	{
	int status;

	status = pCI_Encrypt( length, buffer, buffer );
	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

static int decryptFunction( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							int length )
	{
	int status;

	status = pCI_Decrypt( length, buffer, buffer );
	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

/* Sign/sig check data */

static int signFunction( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						 int length )
	{
	CI_SIGNATURE signature;
	DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) buffer;
	STREAM stream;
	int status;

	assert( length == sizeof( DLP_PARAMS ) );
	assert( dlpParams->inParam1 != NULL && dlpParams->inLen1 == 20 );
	assert( dlpParams->inParam2 == NULL && dlpParams->inLen2 == 0 );
	assert( dlpParams->outParam != NULL && \
			dlpParams->outLen >= ( 2 + 20 ) * 2 );

	/* Sign the hash */
	status = selectPersonalityContext( contextInfoPtr );
	if( status == CI_OK )
		status = pCI_Sign( ( void * ) dlpParams->inParam1, 
						   signature );
	if( status != CI_OK )
		return( ( status == CI_EXEC_FAIL || status == CI_NO_X ) ?
				CRYPT_ERROR_FAILED : mapError( status, CRYPT_ERROR_FAILED ) );

	/* Reformat the signature into the form expected by cryptlib */
	sMemOpen( &stream, dlpParams->outParam, dlpParams->outLen );
	writeSequence( &stream, sizeofInteger( signature, 20 ) +
							sizeofInteger( signature + 20, 20 ) );
	writeInteger( &stream, signature, 20, DEFAULT_TAG );
	writeInteger( &stream, signature + 20, 20, DEFAULT_TAG );
	dlpParams->outLen = stell( &stream );
	assert( cryptStatusOK( sGetStatus( &stream ) ) );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

static int readFixedValue( STREAM *stream, BYTE *buffer )
	{
	int length, status;

	/* Read an integer value and pad it out to a fixed length if necessary */
	status = readInteger( stream, buffer, &length, 20 );
	if( cryptStatusError( status ) )
		return( status );
	if( length < 20 )
		{
		const int delta = 20 - length;

		memmove( buffer, buffer + delta, length );
		memset( buffer, 0, delta );
		}

	return( CRYPT_OK );
	}

static int sigCheckFunction( CONTEXT_INFO *contextInfoPtr, void *buffer, 
							 int length )
	{
	CI_SIGNATURE signature;
	DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) buffer;
	STREAM stream;
	int status;

	assert( length == sizeof( DLP_PARAMS ) );
	assert( dlpParams->inParam1 != NULL && dlpParams->inLen1 == 20 );
	assert( dlpParams->inParam2 != NULL && \
			( dlpParams->formatType == CRYPT_FORMAT_CRYPTLIB && \
			  ( dlpParams->inLen2 >= 42 && dlpParams->inLen2 <= 48 ) ) );
	assert( dlpParams->outParam == NULL && dlpParams->outLen == 0 );

	/* Decode the signature from the cryptlib format */
	sMemConnect( &stream, dlpParams->inParam2, dlpParams->inLen2 );
	status = readSequence( &stream, NULL );
	if( !cryptStatusError( status ) )
		status = readFixedValue( &stream, signature );
	if( !cryptStatusError( status ) )
		status = readFixedValue( &stream, signature + 20 );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_BADDATA );
	sMemDisconnect( &stream );

	/* Verify the signature.  The Fortezza verification code requires that
	   the user supply the y parameter (assuming the use of fixed, shared
	   domain parameters), however this isn't available in non-native
	   contexts since the values are stored in the card.  However, this
	   code is never called anyway since cryptlib always creates native
	   contexts for public keys (there's no point in using the device for
	   these operations since it's quicker to do it natively) */
	status = selectPersonalityContext( contextInfoPtr );
	if( status == CI_OK )
		{
		BYTE yBuffer[ CRYPT_MAX_PKCSIZE + 8 ];
		int yLength;

		yLength = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_y, yBuffer );
		status = pCI_VerifySignature( ( void * ) dlpParams->inParam1, 
									  yLength, yBuffer, signature );
		}
	return( ( status == CI_EXEC_FAIL ) ? \
			CRYPT_ERROR_FAILED : mapError( status, CRYPT_ERROR_FAILED ) );
	}

/****************************************************************************
*																			*
*						 	Mechanism Interface Routines					*
*																			*
****************************************************************************/

/* Perform key agreement.  Since the return value is assumed to be a single 
   blob but we use the presence of a null pointer to denote a dummy export, 
   we can't pass back multi-element length information so we have to encode
   the length as two byte values to handle the wrapped key + UKM */

static const CI_RB Rb = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 
	};

#define encodeLengths( wrappedKeySize, ukmSize ) \
		( ( ( wrappedKeySize ) << 8 ) | ( ukmSize ) )

static int exportKEA( DEVICE_INFO *deviceInfo, 
					  MECHANISM_WRAP_INFO *mechanismInfo )
	{
	MESSAGE_DATA msgData;
	BYTE recipientPublicValue[ 128 + 8 ], ivBuffer[ FORTEZZA_IVSIZE + 8 ];
	void *wrappedKeyPtr = mechanismInfo->wrappedData;
	void *ukmPtr = ( BYTE * ) mechanismInfo->wrappedData + sizeof( CI_KEY );
	int tekIndex, mekIndex, status;

	/* Sanity check the input data */
	assert( ( mechanismInfo->wrappedData == NULL && \
			  mechanismInfo->wrappedDataLength == 0 ) || \
			( mechanismInfo->wrappedDataLength >= \
			  sizeof( CI_KEY ) + sizeof( CI_RA ) ) );
	assert( mechanismInfo->keyData == NULL );
	assert( mechanismInfo->keyDataLength == 0 );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0, 
				mechanismInfo->wrappedDataLength );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		/* Since the return value is assumed to be a single blob but we use
		   the presence of a null pointer to denote a dummy export, we can't
		   pass back multi-element length information so we have to encode
		   the length as two byte values to handle the wrapped key + UKM */
		mechanismInfo->wrappedDataLength = \
					encodeLengths( sizeof( CI_KEY ), sizeof( CI_RA ) );
		return( CRYPT_OK );
		}

	/* Get the public value from the recipient context, the MEK register from 
	   the session key context and find a free key register to work with */
	setMessageData( &msgData, recipientPublicValue, 128 );
	status = krnlSendMessage( mechanismInfo->wrapContext, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_KEY_KEAPUBLICVALUE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->keyContext, 
								  IMESSAGE_GETATTRIBUTE, &mekIndex, 
								  CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusOK( status ) )
		status = findFreeKeyRegister( deviceInfo->deviceFortezza );
	if( cryptStatusError( status ) )
		return( status );
	tekIndex = status;

	/* Generate the Ra value from the caller's private key, and generate the
	   TEK based on the recipients y value.  Note that the generation of the
	   TEK has to immediately follow the generation of Ra because the device
	   state for the TEK generation is carried over from the Ra generation */
	status = selectPersonality( deviceInfo, mechanismInfo->auxContext );
	if( status == CI_OK )
		status = pCI_GenerateRa( ukmPtr );
	if( status == CI_OK )
		status = pCI_GenerateTEK( CI_INITIATOR_FLAG, tekIndex, ukmPtr, 
								  ( void * ) Rb, sizeof( CI_RB ), 
								  recipientPublicValue );
	if( status != CI_OK )
		{
		status = mapError( status, CRYPT_ERROR_FAILED );
		return( status );
		}

	/* Wrap the MEK with the TEK and free the TEK register */
	status = pCI_WrapKey( tekIndex, mekIndex, wrappedKeyPtr );
	pCI_DeleteKey( tekIndex );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_FAILED ) );
	mechanismInfo->wrappedDataLength = \
					encodeLengths( sizeof( CI_KEY ), sizeof( CI_RA ) );

	/* Now that we're past the cryptologic-scrambling TEK-wrapping operation, 
	   we can re-select the MEK and generate an IV for it.  See the 
	   initIVFunction() comments for more details on this */
	status = pCI_SetKey( mekIndex );
	if( status == CI_OK )
		status = pCI_GenerateIV( ivBuffer );
	if( status != CI_OK )
		{
		memset( mechanismInfo->wrappedData, 0, 
				mechanismInfo->wrappedDataLength );
		return( mapError( status, CRYPT_ERROR_FAILED ) );
		}
	setMessageData( &msgData, ivBuffer + FORTEZZA_IVSIZE - 8, 8 );
	status = krnlSendMessage( mechanismInfo->keyContext, 
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_IV );

	return( status );
	}

#if 0	/* 22/09/99 Replaced by mechanism function */
static int keyAgreeOriginatorFunction( CONTEXT_INFO *contextInfoPtr, void *buffer, 
									   int length )
	{
	KEYAGREE_PARAMS *keyAgreeParams = ( KEYAGREE_PARAMS * ) buffer;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	int tekIndex, mekIndex, status;

	/* Check the input parameters */
	if( keyAgreeParams->publicValueLen != sizeof( CI_Y ) )
		return( CRYPT_ERROR_BADDATA );

	/* Get the MEK from the session key context */
	status = krnlSendMessage( keyAgreeParams->sessionKeyContext, 
							  IMESSAGE_GETATTRIBUTE, &mekIndex, 
							  CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusError( status ) )
		return( status );
	
	/* Get the info for the device associated with this context and keep it 
	   locked it while we work with it.  This is necessary because of the 
	   implicit key selection used by the Fortezza crypto library, if we were
	   to unlock the device at any point another thread could enable the use 
	   of a different key */
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlAcquireObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( void ** ) &deviceInfo, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );

	/* Get a free key register to work with */
	tekIndex = findFreeKeyRegister( deviceInfo );
	if( cryptStatusError( tekIndex ) )
		{
		krnlReleaseObject( deviceInfo->objectHandle );
		return( tekIndex );
		}

	/* Generate the Ra value from the caller's private key, and generate the 
	   TEK based on the recipient's y value */
	status = selectPersonalityContext( contextInfoPtr );
	if( status == CI_OK )
		status = pCI_GenerateRa( keyAgreeParams->ukm );
	if( status == CI_OK )
		status = pCI_GenerateTEK( CI_INITIATOR_FLAG, tekIndex, 
								  keyAgreeParams->ukm, ( void * ) Rb, 128, 
								  keyAgreeParams->publicValue );
	if( status != CI_OK )
		{
		status = mapError( status, CRYPT_ERROR_FAILED );
		krnlReleaseObject( deviceInfo->objectHandle );
		return( status );
		}
	keyAgreeParams->ukmLen = sizeof( CI_RA );

	/* Wrap the MEK with the TEK and free the TEK register */
	status = pCI_WrapKey( tekIndex, mekIndex, keyAgreeParams->wrappedKey );
	pCI_DeleteKey( tekIndex );
	krnlReleaseObject( deviceInfo->objectHandle );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_FAILED ) );
	keyAgreeParams->wrappedKeyLen = sizeof( CI_KEY );

	return( CRYPT_OK );
	}
#endif /* 0 */

static int importKEA( DEVICE_INFO *deviceInfo, 
					  MECHANISM_WRAP_INFO *mechanismInfo )
	{
	return( CRYPT_ERROR );
	}

#if 0	/* 22/09/99 Replaced by mechanism function */
static int keyAgreeRecipientFunction( CONTEXT_INFO *contextInfoPtr, void *buffer, 
									  int length )
	{
	KEYAGREE_PARAMS *keyAgreeParams = ( KEYAGREE_PARAMS * ) buffer;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	int tekIndex, mekIndex, status;

	/* Check the input parameters */
	if( keyAgreeParams->publicValueLen != sizeof( CI_Y ) || \
		keyAgreeParams->ukmLen != sizeof( CI_RA ) || \
		keyAgreeParams->wrappedKeyLen != sizeof( CI_KEY ) )
		return( CRYPT_ERROR_BADDATA );

	/* Get the MEK from the session key context */
	status = krnlSendMessage( keyAgreeParams->sessionKeyContext, 
							  IMESSAGE_GETATTRIBUTE, &mekIndex, 
							  CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusError( status ) )
		return( status );
	
	/* Get the info for the device associated with this context and keep it 
	   locked it while we work with it.  This is necessary because of the 
	   implicit key selection used by the Fortezza crypto library, if we were
	   to unlock the device at any point another thread could enable the use 
	   of a different key */
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlAcquireObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( void ** ) &deviceInfo, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );

	/* Get a free key register to work with */
	tekIndex = findFreeKeyRegister( deviceInfo->deviceFortezza );
	if( cryptStatusError( tekIndex ) )
		{
		krnlReleaseObject( deviceInfo->objectHandle );
		return( tekIndex );
		}

	/* Generate the TEK based on the originators y value, Ra, and the 
	   recipient's private key */
	status = selectPersonalityContext( contextInfoPtr );
	if( status == CI_OK )
		status = pCI_GenerateTEK( CI_RECIPIENT_FLAG, tekIndex, 
								  keyAgreeParams->ukm, ( void * ) Rb, 128, 
								  keyAgreeParams->publicValue );

	/* Unwrap the MEK with the TEK and free the TEK register */
	status = pCI_UnwrapKey( tekIndex, mekIndex, keyAgreeParams->wrappedKey );
	pCI_DeleteKey( tekIndex );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_FAILED ) );

	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*						 	Device Capability Routines						*
*																			*
****************************************************************************/

/* The capability information for this device.  We don't do SHA-1 using the
   device since the implementation is somewhat clunky and will be much slower
   than a native one */

static const CAPABILITY_INFO capabilities[] = {
	/* The DSA capabilities */
	{ CRYPT_ALGO_DSA, bitsToBytes( 0 ), "DSA",
		bitsToBytes( 1024 ), bitsToBytes( 1024 ), bitsToBytes( 1024 ), 
		NULL, getDefaultInfo, NULL, NULL, initKeyFunction, generateKeyFunction, 
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
		signFunction, sigCheckFunction },

	/* The Skipjack capabilities.  Note that we're using a LEAF-suppressed IV */
	{ CRYPT_ALGO_SKIPJACK, bitsToBytes( 64 ), "Skipjack",
		bitsToBytes( 80 ), bitsToBytes( 80 ), bitsToBytes( 80 ), 
		NULL, /*initCryptFunction*/getDefaultInfo, NULL, initKeyParamsFunction, initKeyFunction, generateKeyFunction, 
		encryptFunction, decryptFunction, encryptFunction, decryptFunction, 
		encryptFunction, decryptFunction, encryptFunction, decryptFunction },

	/* The KEA capabilities.  The capabilities can't be applied directly but 
	   are used via higher-level mechanisms so the associated function 
	   pointers are all null */
	{ CRYPT_ALGO_KEA, bitsToBytes( 0 ), "KEA",
		bitsToBytes( 1024 ), bitsToBytes( 1024 ), bitsToBytes( 1024 ), 
		NULL, getDefaultInfo, NULL, NULL, NULL, generateKeyFunction },

	/* The end-of-list marker.  This value isn't linked into the 
	   capabilities list when we call initCapabilities() */
	{ CRYPT_ALGO_NONE }, { CRYPT_ALGO_NONE }
	};

static CAPABILITY_INFO_LIST capabilityInfoList[ 4 ];

/* Initialise the capability info */

static void initCapabilities( void )
	{
	int i;

	/* Build the list of available capabilities */
	memset( capabilityInfoList, 0, 
			sizeof( CAPABILITY_INFO_LIST ) * 4 );
	for( i = 0; capabilities[ i ].cryptAlgo != CRYPT_ALGO_NONE && \
				i < FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO ); i++ )
		{
		assert( capabilities[ i ].cryptAlgo == CRYPT_ALGO_KEA || \
				capabilityInfoOK( &capabilities[ i ], FALSE ) );
		
		capabilityInfoList[ i ].info = &capabilities[ i ];
		capabilityInfoList[ i ].next = NULL;
		if( i > 0 )
			capabilityInfoList[ i - 1 ].next = &capabilityInfoList[ i ];
		}
	if( i >= FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO ) )
		retIntError_Void();
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

int setDeviceFortezza( DEVICE_INFO *deviceInfo )
	{
	/* Load the Fortezza driver DLL's if they aren't already loaded */
	if( hFortezza == NULL_HINSTANCE )
		{
		deviceInitFortezza();
		if( hFortezza == NULL_HINSTANCE )
			return( CRYPT_ERROR_OPEN );
		}

	deviceInfo->initFunction = initFunction;
	deviceInfo->shutdownFunction = shutdownFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->getItemFunction = getItemFunction;
	deviceInfo->setItemFunction = setItemFunction;
	deviceInfo->deleteItemFunction = deleteItemFunction;
	deviceInfo->getFirstItemFunction = getFirstItemFunction;
	deviceInfo->getNextItemFunction = getNextItemFunction;
	deviceInfo->getRandomFunction = getRandomFunction;
	deviceInfo->capabilityInfoList = capabilityInfoList;
	deviceInfo->mechanismFunctions = mechanismFunctions;
	deviceInfo->mechanismFunctionCount = \
		FAILSAFE_ARRAYSIZE( mechanismFunctions, MECHANISM_FUNCTION_INFO );

	return( CRYPT_OK );
	}
#endif /* USE_FORTEZZA */
