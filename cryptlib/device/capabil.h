/****************************************************************************
*																			*
*					cryptlib Encryption Capability Header File 				*
*						Copyright Peter Gutmann 1992-2003					*
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

/* Shared functions.  These are used for all native contexts and also by 
   some device types */

int getInfo( const CAPABILITY_INFO_TYPE type, 
			 void *varParam, const int constParam );

/* The structure used to store internal information about the crypto library
   capabilities.  This information is used internally by the library and is
   not available to users */

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

	/* Sometimes the capabilities may be stored as a dynamically-created
	   linked list instead of a static table, so we need to store a pointer
	   to the next element in the list */
	struct CA *next;    			/* Next element in list */
	} CAPABILITY_INFO;
#endif /* _CRYPTCAP_DEFINED */
