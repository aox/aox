/****************************************************************************
*																			*
*							cryptlib DBMS Interface							*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdarg.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "rpc.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keyset/keyset.h"
  #include "../misc/rpc.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "misc/rpc.h"
#endif /* Compiler-specific includes */

/* The size of ID fields.  The keyID size is based on the size of the base64-
   encoded first 128 bits of an SHA-1 hash (the base64 encoding adds up to 2 
   bytes of padding and a byte of null terminator, we strip the padding after 
   encoding so the given encoded size is slightly shorter than normal).  The 
   field size value is encoded into the SQL strings and is also given in text 
   form for this purpose (without the terminator being included).
   
   In addition to the basic field size, we also define the size of the buffer 
   to hold the key ID, with a few bytes of slop space for safety.  This is 
   done with all buffers, but in this case it's actually useful because the 
   general-purpose base64-encoding routines add padding chars at the end for
   the standard case and then truncate the encoded text as a special-case for 
   raw base64 strings, which means that they produce a bit more output than 
   the fixed keyID size */

#define DBXKEYID_SIZE			16		/* Full keyID = 128 bits */
#define MAX_ENCODED_DBXKEYID_SIZE 23	/* base64-encoded + '\0' */
#define TEXT_DBXKEYID_SIZE		"22"
#define DBXKEYID_BUFFER_SIZE	32		/* Buffer for encoded keyID */

/* The maximum SQL query size, being is the size of the DN and other 
   components, the key ID's, and the key itself */

#define MAX_SQL_QUERY_SIZE		( ( 7 * CRYPT_MAX_TEXTSIZE ) + \
								  ( 3 * MAX_ENCODED_DBXKEYID_SIZE ) + \
								  MAX_ENCODED_CERT_SIZE + 128 )

/* When performing a query the database glue code limits the maximum returned
   data size to a certain size, the following define allows us to declare a
   fixed-size buffer that we know will always be big enough */

#define MAX_QUERY_RESULT_SIZE	MAX_ENCODED_CERT_SIZE

/* Database status flags.  The update active flag is required because we can 
   sometimes run into a situation where an update falls through to an abort 
   without ever having been begun, this happens if there's a sequence of misc 
   setup operations taking place and one of them fails before we begin the 
   update.  Although it'd be better if the caller handled this, in practice 
   it'd mean passing extra status information (failed vs.failed but need to 
   abort a commenced update) across a number of different functions, to avoid 
   this we record whether an update has begun and if not skip an abort 
   operation if there's no update currently in progress.
   
   Cert stores are designated by two flags, a main one for standard database/
   cert store differentiation and a secondary one that indicates that it's
   a cert store opened as a standard database (for example for read-only 
   access in a key server).  In this case it's possible to perform extended
   queries on fields that aren't present in standard databases, so we set
   the secondary flags to indicate that extended queries are possible even
   though cert store functionality isn't present */

#define DBMS_FLAG_NONE			0x00
#define DBMS_FLAG_BINARYBLOBS	0x01	/* DBMS supports blobs */
#define DBMS_FLAG_UPDATEACTIVE	0x02	/* Ongoing update in progress */
#define DBMS_FLAG_QUERYACTIVE	0x04	/* Ongoing query in progress */
#define DBMS_FLAG_CERTSTORE		0x08	/* Full cert store */
#define DBMS_FLAG_CERTSTORE_FIELDS 0x10	/* Cert store fields */

/* Database feature information returned when the keyset is opened */

#define DBMS_HAS_NONE			0x00
#define DBMS_HAS_BINARYBLOBS	0x01	/* DBMS supports binary blobs */

/* The certstore and binary blobs flags are checked often enough that we 
   define a macro for them */

#define hasBinaryBlobs( dbmsInfo ) \
		( ( dbmsInfo )->flags & DBMS_FLAG_BINARYBLOBS )
#define isCertStore( dbmsInfo ) \
		( ( dbmsInfo )->flags & DBMS_FLAG_CERTSTORE )

/* When we add or read information to/from a table we sometimes have to
   specify type information which is an integer value, however SQL requires
   that things be set out as character strings so we use the following
   defines to provide the string form of the value for insertion into an SQL
   query.  Unfortunately we can't check this at compile time so we have to
   check it via an assertion in the CA dispatch function */

#define TEXT_CERTTYPE_REQUEST_CERT			"5"
#define TEXT_CERTTYPE_REQUEST_REVOCATION	"6"

#define TEXT_CERTACTION_CREATE				"1"
#define TEXTCH_CERTACTION_ADDUSER			'5'
#define TEXTCH_CERTACTION_REQUEST_CERT		'6'
#define TEXT_CERTACTION_REQUEST_RENEWAL		"7"
#define TEXTCH_CERTACTION_REQUEST_RENEWAL	'7'
#define TEXT_CERTACTION_CERT_CREATION		"9"

/* The ways in which we can add a cert object to a table.  Normally we just
   add the cert as is, however if we're awaiting confirmation from a user
   before we can complete the cert issue process we perform a partial add
   that marks the cert as not quite ready for use yet.  A variant of this
   is when we're renewing a cert (i.e.reissuing it with the same key, which
   is really bad but required by some cert mismanagement protocols), in which
   case we have to process the update as a multi-stage process because we're
   replacing an existing cert with one which is exactly the same as far as
   the uniqueness constraints on the cert store are concerned */

typedef enum {
	CERTADD_NORMAL,				/* Standard one-step add */
	CERTADD_PARTIAL,			/* Partial add */
	CERTADD_PARTIAL_RENEWAL,	/* Partial add with cert replacement to follow */
	CERTADD_RENEWAL_COMPLETE	/* Completion of renewal */
	} CERTADD_TYPE;

/* A structure to parse the database access information into so that it can 
   be used by backend-specific connect functions */

typedef struct {
	char userBuffer[ CRYPT_MAX_TEXTSIZE + 1 ], *user;
	char passwordBuffer[ CRYPT_MAX_TEXTSIZE + 1 ], *password;
	char serverBuffer[ CRYPT_MAX_TEXTSIZE + 1 ], *server;
	char nameBuffer[ CRYPT_MAX_TEXTSIZE + 1 ], *name;
	int userLen, passwordLen, serverLen, nameLen;
	} DBMS_NAME_INFO;

/* Macros to make use of the DBMS access functions less painful.  These 
   assume the existence of a variable 'dbmsInfo' that contains DBMS access
   state information */

#define dbmsOpen( name, options ) \
		dbmsInfo->openDatabaseFunction( dbmsInfo, name, options )
#define dbmsClose() \
		dbmsInfo->closeDatabaseFunction( dbmsInfo )
#define dbmsStaticUpdate( command ) \
		dbmsInfo->performStaticUpdateFunction( dbmsInfo, command )
#define dbmsUpdate( command, boundData, boundDataLen, boundDate, updateType ) \
		dbmsInfo->performUpdateFunction( dbmsInfo, command, boundData, \
										 boundDataLen, boundDate, updateType )
#define dbmsStaticQuery( command, queryType ) \
		dbmsInfo->performStaticQueryFunction( dbmsInfo, command, queryType )
#define dbmsQuery( command, data, dataLength, date, queryType ) \
		dbmsInfo->performQueryFunction( dbmsInfo, command, data, dataLength, \
										date, queryType )

/* Other non-macro functions */

void dbmsFormatSQL( char *buffer, const char *format, ... );
int dbmsFormatQuery( char *output, const char *input, const int inputLength,
					 const int maxLength );
int dbmsParseName( DBMS_NAME_INFO *nameInfo, const char *name,
				   const int lengthMarker );

/* Prototypes for interface routines in dbxdbms.c */

int initDbxSession( KEYSET_INFO *keysetInfo, const CRYPT_KEYSET_TYPE type );
int endDbxSession( KEYSET_INFO *keysetInfo );
int parseDatabaseName( DBMS_NAME_INFO *nameInfo, const char *name,
					   const int lengthMarker );

/* Prototypes for routines in dbxdbx.c */

char *getKeyName( const CRYPT_KEYID_TYPE keyIDtype );
int getKeyID( char *keyIDbuffer, const CRYPT_HANDLE cryptHandle,
			  const CRYPT_ATTRIBUTE_TYPE keyIDtype );
int getCertKeyID( char *keyID, const CRYPT_CERTIFICATE iCryptCert );
int getItemData( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iCertificate,
				 int *stateInfo, const char *keyName, const char *keyValue,
				 const KEYMGMT_ITEM_TYPE itemType, const int options );
int addCert( DBMS_INFO *dbmsInfo, const CRYPT_HANDLE iCryptHandle,
			 const CRYPT_CERTTYPE_TYPE certType, const CERTADD_TYPE addType,
			 const DBMS_UPDATE_TYPE updateType );
int addCRL( DBMS_INFO *dbmsInfo, const CRYPT_CERTIFICATE iCryptCRL,
			const CRYPT_CERTIFICATE iCryptRevokeCert,
			const DBMS_UPDATE_TYPE updateType );

/* Prototypes for CA management routines in dbxca.c */

int updateCertLog( DBMS_INFO *dbmsInfo, const int action, const char *certID, 
				   const char *reqCertID, const char *subjCertID, 
				   const void *data, const int dataLength, 
				   const DBMS_UPDATE_TYPE updateType );
int caAddCertRequest( DBMS_INFO *dbmsInfo, 
					  const CRYPT_CERTIFICATE iCertRequest,
					  const CRYPT_CERTTYPE_TYPE requestType, 
					  const BOOLEAN isRenewal );
int caAddPKIUser( DBMS_INFO *dbmsInfo, const CRYPT_CERTIFICATE iPkiUser );
int caGetIssuingUser( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iPkiUser,
					  const char *initialCertID );
int initDBMSCA( KEYSET_INFO *keysetInfo );
