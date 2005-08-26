/****************************************************************************
*																			*
*					cryptlib Encryption Capability Header File 				*
*						Copyright Peter Gutmann 1992-2005					*
*																			*
****************************************************************************/

#ifndef _CRYPTCAP_DEFINED

#define _CRYPTCAP_DEFINED

/* The CONTEXT_INFO structure is only visible inside modules that have access
   to context internals, if we use it anywhere else we just treat it as a
   generic void *.  In addition since the CONTEXT_INFO contains the 
   capability info struct, it can't be declared yet at this point so we have 
   to provide a forward declaration for it */

#ifdef _CRYPTCTX_DEFINED
  struct CI;
  #define CI_STRUCT		struct CI
#else
  #define CI_STRUCT		void

  int initKeyParams( CI_STRUCT *contextInfoPtr, const void *iv,
					 const int ivLength, const CRYPT_MODE_TYPE mode );
#endif /* _CRYPTCTX_DEFINED */

/* The information returned by the capability get-info function */

typedef enum {
	CAPABILITY_INFO_NONE,			/* No info */
	CAPABILITY_INFO_KEYSIZE,		/* Key size for this algorithm */
	CAPABILITY_INFO_STATESIZE,		/* Size of algorithm state info */
	CAPABILITY_INFO_LAST			/* Last possible capability info type */
	} CAPABILITY_INFO_TYPE;

/* The structure used to store information about the crypto capabilities */

typedef struct CA {
	/* Basic identification information for the algorithm */
	const CRYPT_ALGO_TYPE cryptAlgo;/* The encryption algorithm */
	const int blockSize;			/* The basic block size of the algorithm */
	const char *algoName;			/* Algorithm name */

	/* Keying information.  Note that the maximum sizes may vary (for
	   example for two-key triple DES vs.three-key triple DES) so the
	   crypt query functions should be used to determine the actual size
	   for a particular context rather than just using maxKeySize */
	const int minKeySize;			/* Minimum key size in bytes */
	const int keySize;				/* Recommended key size in bytes */
	const int maxKeySize;			/* Maximum key size in bytes */

	/* The functions for implementing the algorithm */
	int ( *selfTestFunction )( void );
	int ( *getInfoFunction )( const CAPABILITY_INFO_TYPE type, 
							  void *varParam, const int constParam );
	int ( *endFunction )( CI_STRUCT *cryptInfoPtr );
	int ( *initKeyParamsFunction )( CI_STRUCT *cryptInfoPtr, const void *iv,
									const int ivLength, const CRYPT_MODE_TYPE mode );
	int ( *initKeyFunction )( CI_STRUCT *cryptInfoPtr, const void *key,
							  const int keyLength );
	int ( *generateKeyFunction )( CI_STRUCT *cryptInfoPtr, const int keySizeBits );
	int ( *encryptFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *decryptFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *encryptCBCFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *decryptCBCFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *encryptCFBFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *decryptCFBFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *encryptOFBFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *decryptOFBFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *signFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *sigCheckFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );

	/* Non-native implementations may require extra parameters (for example
	   to specify the algorithm and mode in the manner required by the
	   non-native implementation), the following values can be used to store
	   these parameters */
	const int param1, param2, param3, param4;
	} CAPABILITY_INFO;

/* An encapsulating list type for the list of capabilities */

typedef struct CL {
	const CAPABILITY_INFO *info;
	struct CL *next;
	}  CAPABILITY_INFO_LIST;

/* Since cryptlib's CAPABILITY_INFO is fixed, all of the fields are declared
   const so that they'll be allocated in the code segment.  This doesn't quite 
   work for some types of crypto devices since things like the available key 
   lengths can vary depending on the underlying hardware or software, so we 
   provide an equivalent structure that makes the variable fields non-const.  
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
	int ( *endFunction )( CI_STRUCT *cryptInfoPtr );
	int ( *initKeyParamsFunction )( CI_STRUCT *cryptInfoPtr, const void *iv,
									const int ivLength, const CRYPT_MODE_TYPE mode );
	int ( *initKeyFunction )( CI_STRUCT *cryptInfoPtr, const void *key,
							  const int keyLength );
	int ( *generateKeyFunction )( CI_STRUCT *cryptInfoPtr, const int keySizeBits );
	int ( *encryptFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *decryptFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *encryptCBCFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *decryptCBCFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *encryptCFBFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *decryptCFBFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *encryptOFBFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *decryptOFBFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *signFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );
	int ( *sigCheckFunction )( CI_STRUCT *cryptInfoPtr, BYTE *buffer, int length );

	int param1, param2, param3, param4;	/* Non-const */
	} VARIABLE_CAPABILITY_INFO;

/* Prototypes for capability access functions */

typedef const CAPABILITY_INFO * ( *GETCAPABILITY_FUNCTION )( void );

const CAPABILITY_INFO *get3DESCapability( void );
const CAPABILITY_INFO *getAESCapability( void );
const CAPABILITY_INFO *getBlowfishCapability( void );
const CAPABILITY_INFO *getCASTCapability( void );
const CAPABILITY_INFO *getDESCapability( void );
const CAPABILITY_INFO *getIDEACapability( void );
const CAPABILITY_INFO *getRC2Capability( void );
const CAPABILITY_INFO *getRC4Capability( void );
const CAPABILITY_INFO *getRC5Capability( void );
const CAPABILITY_INFO *getSkipjackCapability( void );

const CAPABILITY_INFO *getMD2Capability( void );
const CAPABILITY_INFO *getMD4Capability( void );
const CAPABILITY_INFO *getMD5Capability( void );
const CAPABILITY_INFO *getRipemd160Capability( void );
const CAPABILITY_INFO *getSHA1Capability( void );
const CAPABILITY_INFO *getSHA2Capability( void );

const CAPABILITY_INFO *getHmacMD5Capability( void );
const CAPABILITY_INFO *getHmacRipemd160Capability( void );
const CAPABILITY_INFO *getHmacSHA1Capability( void );

const CAPABILITY_INFO *getDHCapability( void );
const CAPABILITY_INFO *getDSACapability( void );
const CAPABILITY_INFO *getElgamalCapability( void );
const CAPABILITY_INFO *getRSACapability( void );

/* Fallback function to get context-specific information that isn't specific
   to a particular context.  The initial query goes to the context, if that
   doesn't want to handle it it passes it on to the default handler */

int getDefaultInfo( const CAPABILITY_INFO_TYPE type, 
					void *varParam, const int constParam );

#endif /* _CRYPTCAP_DEFINED */
