/****************************************************************************
*																			*
*					  cryptlib Device Interface Header File 				*
*						Copyright Peter Gutmann 1998-2002					*
*																			*
****************************************************************************/

#ifndef _DEVICE_DEFINED

#define _DEVICE_DEFINED

/* The maximum length of error message we can store */

#define MAX_ERRMSG_SIZE		512

/* Device information flags.  The "needs login" flag is a general device
   flag which indicates that this type of device needs a user login before
   it can be used and is set when the device is first opened, the "logged in"
   flag is an ephemeral flag which indicates whether the user is currently
   logged in.  The "device active" flag indicates that a session with the
   device is currently active and needs to be shut down when the device
   object is destroyed */

#define DEVICE_NEEDSLOGIN	0x0001	/* User must log in to use dev.*/
#define DEVICE_READONLY		0x0002	/* Device can't be written to */
#define DEVICE_REMOVABLE	0x0004	/* Device is removable */
#define DEVICE_ACTIVE		0x0008	/* Device is currently active */
#define DEVICE_LOGGEDIN		0x0010	/* User is logged into device */
#define DEVICE_TIME			0x0020	/* Device has on-board time source */

/* Devices implement mechanisms in the same way that contexts implement 
   actions.  Since the mechanism space is sparse, dispatching is handled by
   looking up the required mechanism in a table of (action, mechanism, 
   function) triples.  The table is sorted by order of most-frequently-used 
   mechanisms to speed things up, although the overhead is vanishingly small 
   anyway */

typedef int ( *MECHANISM_FUNCTION )( void *deviceInfoPtr,
									 void *mechanismInfo );
typedef struct {
	const MESSAGE_TYPE action;
	const MECHANISM_TYPE mechanism;
	const MECHANISM_FUNCTION function;
	} MECHANISM_FUNCTION_INFO;

/* Devices can also be used to create further objects.  Most can only create
   contexts, but the system object can create any kind of object */

typedef int ( *CREATEOBJECT_FUNCTION )( MESSAGE_CREATEOBJECT_INFO *objectInfo,
										const void *auxDataPtr,
										const int auxValue );
typedef struct {
	const OBJECT_TYPE type;
	const CREATEOBJECT_FUNCTION function;
	} CREATEOBJECT_FUNCTION_INFO;

/* The internal fields in a deviec that hold data for the various keyset
   types.   These are implemented as a union to conserve memory with some of 
   the more data-intensive types such as Fortezza cards.  In addition the 
   structures provide a convenient way to group the device type-specific 
   parameters */

typedef struct {
	/* General device information */
	int minPinSize, maxPinSize;		/* Minimum, maximum PIN lengths */
	char labelBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Device label */

	/* Device type-specific information */
	unsigned long hSession;			/* Session handle */
	long slotID;					/* Slot ID for multi-slot device */
	int deviceNo;					/* Index into PKCS #11 token table */
	char defaultSSOPIN[ CRYPT_MAX_TEXTSIZE + 1 ];	/* SSO PIN from dev.init */

	/* Last-error information returned from lower-level code */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];
	} PKCS11_INFO;

typedef struct {
	/* General device information */
	char labelBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Device label */

	/* Device type-specific information */
	int hProv;						/* CryptoAPI provider handle */
	int hPrivateKey;				/* Key for session key import/export */
	int privateKeySize;				/* Size of import/export key */

	/* Last-error information returned from lower-level code */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];
	} CRYPTOAPI_INFO;

typedef struct {
	/* General device information */
	int minPinSize, maxPinSize;		/* Minimum, maximum PIN lengths */
	char labelBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Device label */

	/* Device type-specific information */
	int socketIndex;				/* Slot index for multi-slot reader */
	long largestBlockSize;			/* Largest single data block size */
	long keyRegisterFlags;			/* Bitfield of key regs.in use */
	int keyRegisterCount;			/* Number of key registers */

	/* Device personality information */
	void *personalities;			/* Device personality list */
	int personalityCount;			/* Number of personalities */
	void *certHashes;				/* Hashes of certs in card */
	BOOLEAN certHashesInitialised;	/* Whether hashes are initialised */
	int currentPersonality;			/* Currently selected personality */

	/* Other information */
	BYTE leafString[ 16 ];			/* LEAF-suppressed string */
	char initPIN[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Initialisation PIN */

	/* Last-error information returned from lower-level code */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];
	} FORTEZZA_INFO;

/* Defines to make access to the union fields less messy */

#define devicePKCS11	deviceInfo.pkcs11Info
#define deviceCryptoAPI	deviceInfo.cryptoapiInfo
#define deviceFortezza	deviceInfo.fortezzaInfo

/* The structure which stores information on a device */

typedef struct DI {
	/* General device information.  Alongside various handles used to access
	   the device we also record whether the user has authenticated
	   themselves to the device since some devices have multiple user-access
	   states and the user needs to be logged out of one state before they
	   can log in to another state.  In addition we also record the device
	   label which the caller can query for use in prompts displayed to the
	   user */
	CRYPT_DEVICE_TYPE type;			/* Device type */
	int flags;						/* Device information flags */
	char *label;					/* Device label */

	/* Each device provides various capabilities which are held in the 
	   following list.  When we need to create an object via the device, we
	   look up the requirements in the capability info and feed it to
	   createObjectFromCapability() */
	const void FAR_BSS *capabilityInfo;

	/* Device type-specific information */
	union {
		PKCS11_INFO *pkcs11Info;
		CRYPTOAPI_INFO *cryptoapiInfo;
		FORTEZZA_INFO *fortezzaInfo;
		} deviceInfo;

	/* Pointers to device access methods */
	int ( *initFunction )( struct DI *deviceInfo, const char *name,
						   const int nameLength );
	void ( *shutdownFunction )( struct DI *deviceInfo );
	int ( *controlFunction )( struct DI *deviceInfo,
							  const CRYPT_ATTRIBUTE_TYPE type,
							  const void *data, const int dataLength );
	int ( *getItemFunction )( struct DI *deviceInfo,
							  CRYPT_CONTEXT *iCryptContext,
							  const KEYMGMT_ITEM_TYPE itemType,
							  const CRYPT_KEYID_TYPE keyIDtype,
							  const void *keyID, const int keyIDlength,
							  void *auxInfo, int *auxInfoLength, 
							  const int flags );
	int ( *setItemFunction )( struct DI *deviceInfo,
							  const CRYPT_HANDLE iCryptHandle );
	int ( *deleteItemFunction )( struct DI *deviceInfo,
								 const KEYMGMT_ITEM_TYPE itemType,
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength );
	int ( *getFirstItemFunction )( struct DI *deviceInfo, 
								   CRYPT_CERTIFICATE *iCertificate,
								   int *stateInfo, 
								   const CRYPT_KEYID_TYPE keyIDtype,
								   const void *keyID, const int keyIDlength,
								   const KEYMGMT_ITEM_TYPE itemType, 
								   const int options );
	int ( *getNextItemFunction )( struct DI *deviceInfo, 
								  CRYPT_CERTIFICATE *iCertificate,
								  int *stateInfo, const int options );
	int ( *getRandomFunction)( struct DI *deviceInfo, void *buffer,
							   const int length );

	/* Information for the system device */
	const MECHANISM_FUNCTION_INFO *mechanismFunctions;
	const CREATEOBJECT_FUNCTION_INFO *createObjectFunctions;
	void *randomInfo;

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* The object's handle and the handle of the user who owns this object.
	   The former is used when sending messages to the object when only the 
	   xxx_INFO is available, the latter is used to avoid having to fetch the
	   same information from the system object table */
	CRYPT_HANDLE objectHandle;
	CRYPT_USER ownerHandle;

	/* Variable-length storage for the type-specific data */
	DECLARE_VARSTRUCT_VARS;
	} DEVICE_INFO;

/* Prototypes for the capability info sanity-check function in crypt.c.  This
   function is only called via an assert() and isn't used in non-debug builds.
   The asymmetricOK flag indicates that the capabilities can have asymmetric
   functionality, for example sign is supported but sig.check isn't (this is
   required for some tinkertoy implementations in crypto tokens which support 
   bare-minimum functionality such as RSA private-key ops and nothing else) */

BOOLEAN capabilityInfoOK( const void *capabilityInfoPtr, 
						  const BOOLEAN asymmetricOK );

/* Prototypes for functions in asn1keys.c */

int writeFlatPublicKey( void *buffer, const int bufMaxSize, 
						const CRYPT_ALGO_TYPE cryptAlgo, 
						const void *component1, const int component1Length,
						const void *component2, const int component2Length,
						const void *component3, const int component3Length,
						const void *component4, const int component4Length );

/* Prototypes for the crypto mechanism functions supported by various 
   devices.  These are cryptlib-native mechanisms, some devices override
   these with device-specific implementations */

int derivePKCS5( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int derivePKCS12( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int deriveSSL( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int deriveTLS( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int deriveCMP( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int derivePGP( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int signPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int sigcheckPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int exportPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int exportPKCS1PGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importPKCS1PGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int exportCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int exportPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int exportPrivateKeyPKCS8( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importPrivateKeyPKCS8( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importPrivateKeyPGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importPrivateKeyOpenPGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );

/* Prototypes for device mapping functions */

int setDeviceCEI( DEVICE_INFO *deviceInfo );
#ifdef USE_FORTEZZA
  int deviceInitFortezza( void );
  void deviceEndFortezza( void );
  int setDeviceFortezza( DEVICE_INFO *deviceInfo );
#else
  #define deviceInitFortezza()			CRYPT_OK
  #define deviceEndFortezza()
  #define setDeviceFortezza( x )		CRYPT_ARGERROR_NUM1
#endif /* USE_FORTEZZA */
#ifdef USE_PKCS11
  int deviceInitPKCS11( void );
  void deviceEndPKCS11( void );
  int setDevicePKCS11( DEVICE_INFO *deviceInfo, const char *name,
					   const int nameLength );
#else
  #define deviceInitPKCS11()			CRYPT_OK
  #define deviceEndPKCS11()
  #define setDevicePKCS11( x, y, z )	CRYPT_ARGERROR_NUM1
#endif /* USE_PKCS11 */
#ifdef USE_CRYPTOAPI
  int deviceInitCryptoAPI( void );
  void deviceEndCryptoAPI( void );
  int setDeviceCryptoAPI( DEVICE_INFO *deviceInfo, const char *name, 
						  const int nameLength );
#else
  #define deviceInitCryptoAPI()			CRYPT_OK
  #define deviceEndCryptoAPI()
  #define setDeviceCryptoAPI( x, y, z )	CRYPT_ARGERROR_NUM1
#endif /* USE_CRYPTOAPI */
int setDeviceSystem( DEVICE_INFO *deviceInfo );

#endif /* _DEVICE_DEFINED */
