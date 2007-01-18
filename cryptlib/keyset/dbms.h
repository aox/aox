/****************************************************************************
*																			*
*							cryptlib DBMS Interface							*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#include <stdarg.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "rpc.h"
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
#define MAX_ENCODED_DBXKEYID_SIZE 22	/* base64-encoded key ID */
#define TEXT_DBXKEYID_SIZE		"22"
#define DBXKEYID_BUFFER_SIZE	32		/* Buffer for encoded keyID */

/* Because the base64 decoding maps m -> n bytes, m != n, it may overshoot
   by a few bytes if we encounter maliciously-constructed input.  To make 
   sure that this doesn't cause a buffer overflow, we declare the buffer 
   size a bit larger to allow a small overrun during decoding, so the buffer 
   size is declared as xxx_SIZE + BASE64_OVFL_SIZE while the maxLength 
   parameter passed to the base64 decode routines is xxx_SIZE */

#define BASE64_OVFL_SIZE		16		/* Overflow space for base64 decode */

/* The maximum SQL query size, being the sum of the sizes of the DN and 
   other components, the key ID's, and the key itself */

#define MAX_SQL_QUERY_SIZE		( ( 7 * CRYPT_MAX_TEXTSIZE ) + \
								  ( 3 * MAX_ENCODED_DBXKEYID_SIZE ) + \
								  MAX_ENCODED_CERT_SIZE + 128 )

/* For most of the queries that don't add cert data we don't need to use the 
   worst-case buffer size, so we define an alternative smaller-size buffer for
   use with standard queries */

#define STANDARD_SQL_QUERY_SIZE	256

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
   a cert store opened as a standard database, for example when it's being 
   used for read-only access in a key server.  In this case it's possible to 
   perform extended queries on fields that aren't present in standard 
   databases, so we set the secondary flags to indicate that extended queries 
   are possible even though cert store functionality isn't present */

#define DBMS_FLAG_NONE			0x00
#define DBMS_FLAG_BINARYBLOBS	0x01	/* DBMS supports blobs */
#define DBMS_FLAG_UPDATEACTIVE	0x02	/* Ongoing update in progress */
#define DBMS_FLAG_QUERYACTIVE	0x04	/* Ongoing query in progress */
#define DBMS_FLAG_CERTSTORE		0x08	/* Full cert store */
#define DBMS_FLAG_CERTSTORE_FIELDS 0x10	/* Cert store fields */

/* Database feature information returned when the keyset is opened */

#define DBMS_HAS_NONE			0x00
#define DBMS_HAS_BINARYBLOBS	0x01	/* DBMS supports binary blobs */
#define DBMS_HAS_NOWRITE		0x02	/* DBMS doesn't allow write access */
#define DBMS_HAS_PRIVILEGES		0x04	/* DBMS supports GRANT/REVOKE */

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
#define TEXT_CERTACTION_REQUEST_CERT		"7"
#define TEXTCH_CERTACTION_REQUEST_CERT		'7'
#define TEXT_CERTACTION_REQUEST_RENEWAL		"8"
#define TEXTCH_CERTACTION_REQUEST_RENEWAL	'8'
#define TEXT_CERTACTION_CERT_CREATION		"10"

/* Special escape strings used in database keys to indicate that the value is
   physically but not logically present.  This is used to handle (currently-)
   incomplete cert issues and similar events where intermediate state info 
   has to be stored in the database but the object in question isn't ready 
   for use yet */

#define KEYID_ESC1				"--"
#define KEYID_ESC2				"##"
#define KEYID_ESC_SIZE			2

/* The ways in which we can add a cert object to a table.  Normally we just
   add the cert as is, however if we're awaiting confirmation from a user
   before we can complete the cert issue process we perform a partial add
   that marks the cert as not quite ready for use yet.  A variant of this
   is when we're renewing a cert (i.e.re-issuing it with the same key, which
   is really bad but required by some cert mismanagement protocols), in 
   which case we have to process the update as a multi-stage process because 
   we're replacing an existing cert with one which is exactly the same as 
   far as the uniqueness constraints on the cert store are concerned */

typedef enum {
	CERTADD_NORMAL,				/* Standard one-step add */
	CERTADD_PARTIAL,			/* Partial add */
	CERTADD_PARTIAL_RENEWAL,	/* Partial add with cert replacement to follow */
	CERTADD_RENEWAL_COMPLETE,	/* Completion of renewal */
	CERTADD_LAST				/* Last valid cert-add type */
	} CERTADD_TYPE;

/* In order to make reporting of parameter errors in the multi-parameter 
   CA management function easier, we provide symbolic defines mapping the 
   CA management-specific parameter type to its corresponding parameter 
   error type */

#define CAMGMT_ARGERROR_CAKEY		CRYPT_ARGERROR_NUM1
#define CAMGMT_ARGERROR_REQUEST		CRYPT_ARGERROR_NUM2
#define CAMGMT_ARGERROR_ACTION		CRYPT_ARGERROR_VALUE

/* A structure to parse the database access information into so that it can 
   be used by backend-specific connect functions */

typedef struct {
	char userBuffer[ CRYPT_MAX_TEXTSIZE + 8 ], *user;
	char passwordBuffer[ CRYPT_MAX_TEXTSIZE + 8 ], *password;
	char serverBuffer[ CRYPT_MAX_TEXTSIZE + 8 ], *server;
	char nameBuffer[ CRYPT_MAX_TEXTSIZE + 8 ], *name;
	int userLen, passwordLen, serverLen, nameLen;
	} DBMS_NAME_INFO;

/* Macros to make use of the DBMS access functions less painful.  These 
   assume the existence of a variable 'dbmsInfo' that contains DBMS access
   state information */

#define dbmsOpen( name, options, featureFlags ) \
		dbmsInfo->openDatabaseFunction( dbmsInfo, name, options, featureFlags )
#define dbmsClose() \
		dbmsInfo->closeDatabaseFunction( dbmsInfo )
#define dbmsStaticUpdate( command ) \
		dbmsInfo->performStaticUpdateFunction( dbmsInfo, command )
#define dbmsUpdate( command, boundData, boundDataLen, boundDate, updateType ) \
		dbmsInfo->performUpdateFunction( dbmsInfo, command, boundData, \
										 boundDataLen, boundDate, updateType )
#define dbmsStaticQuery( command, queryEntry, queryType ) \
		dbmsInfo->performStaticQueryFunction( dbmsInfo, command, queryEntry, \
											  queryType )
#define dbmsQuery( command, data, dataLength, queryData, queryDataLength, queryDate, queryEntry, queryType ) \
		dbmsInfo->performQueryFunction( dbmsInfo, command, data, dataLength, \
										queryData, queryDataLength, queryDate, \
										queryEntry, queryType )

int cmdClose( void *stateInfo, COMMAND_INFO *cmd );
int cmdGetErrorInfo( void *stateInfo, COMMAND_INFO *cmd );
int cmdOpen( void *stateInfo, COMMAND_INFO *cmd );
int cmdQuery( void *stateInfo, COMMAND_INFO *cmd );
int cmdUpdate( void *stateInfo, COMMAND_INFO *cmd );

/* Other non-macro functions */

void dbmsFormatSQL( char *buffer, const int bufMaxLen, 
					const char *format, ... );
int dbmsFormatQuery( char *output, const int outMaxLength, 
					 const char *input, const int inputLength );
int dbmsParseName( DBMS_NAME_INFO *nameInfo, const char *name,
				   const int lengthMarker );

/* Prototypes for interface routines in dbms.c */

int initDbxSession( KEYSET_INFO *keysetInfo, const CRYPT_KEYSET_TYPE type );
int endDbxSession( KEYSET_INFO *keysetInfo );
int parseDatabaseName( DBMS_NAME_INFO *nameInfo, const char *name,
					   const int lengthMarker );

/* Prototypes for functions in dbx_rd/wr.c */

void initDBMSread( KEYSET_INFO *keysetInfo );
void initDBMSwrite( KEYSET_INFO *keysetInfo );

/* Prototypes for routines in dbx_misc.c */

char *getKeyName( const CRYPT_KEYID_TYPE keyIDtype );
char *getTableName( const KEYMGMT_ITEM_TYPE itemType );
int makeKeyID( char *keyIDbuffer, const int keyIDbufSize,
			   const CRYPT_KEYID_TYPE keyIDtype, 
			   const void *keyID, const int keyIDlength );
int getKeyID( char *keyIDbuffer, const CRYPT_HANDLE cryptHandle,
			  const CRYPT_ATTRIBUTE_TYPE keyIDtype );
int getCertKeyID( char *keyID, const CRYPT_CERTIFICATE iCryptCert );
int resetErrorInfo( DBMS_INFO *dbmsInfo );
int getItemData( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iCertificate,
				 int *stateInfo, const CRYPT_KEYID_TYPE keyIDtype, 
				 const char *keyValue, const int keyValueLength, 
				 const KEYMGMT_ITEM_TYPE itemType, const int options );
int addCert( DBMS_INFO *dbmsInfo, const CRYPT_HANDLE iCryptHandle,
			 const CRYPT_CERTTYPE_TYPE certType, const CERTADD_TYPE addType,
			 const DBMS_UPDATE_TYPE updateType );
int addCRL( DBMS_INFO *dbmsInfo, const CRYPT_CERTIFICATE iCryptCRL,
			const CRYPT_CERTIFICATE iCryptRevokeCert,
			const DBMS_UPDATE_TYPE updateType );

/* Prototypes for routines in ca_add.c */

BOOLEAN checkRequest( const CRYPT_CERTIFICATE iCertRequest,
					  const CRYPT_CERTACTION_TYPE action );
int caAddCertRequest( DBMS_INFO *dbmsInfo, 
					  const CRYPT_CERTIFICATE iCertRequest,
					  const CRYPT_CERTTYPE_TYPE requestType, 
					  const BOOLEAN isRenewal );
int caAddPKIUser( DBMS_INFO *dbmsInfo, const CRYPT_CERTIFICATE iPkiUser );
int caDeletePKIUser( DBMS_INFO *dbmsInfo, const CRYPT_KEYID_TYPE keyIDtype,
					 const void *keyID, const int keyIDlength );

/* Prototypes for routines in ca_issue.c */

int completeCertRenewal( DBMS_INFO *dbmsInfo,
						 const CRYPT_CERTIFICATE iReplaceCertificate );
int caIssueCert( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iCertificate,
				 const CRYPT_CERTIFICATE caKey,
				 const CRYPT_CERTIFICATE iCertRequest,
				 const CRYPT_CERTACTION_TYPE action );
int caIssueCertComplete( DBMS_INFO *dbmsInfo, 
						 const CRYPT_CERTIFICATE iCertificate,
						 const CRYPT_CERTACTION_TYPE action );

/* Prototypes for routines in ca_rev.c */

int revokeCertDirect( DBMS_INFO *dbmsInfo,
					  const CRYPT_CERTIFICATE iCertificate,
					  const CRYPT_CERTACTION_TYPE action );
int caRevokeCert( DBMS_INFO *dbmsInfo, const CRYPT_CERTIFICATE iCertRequest,
				  const CRYPT_CERTIFICATE iCertificate,
				  const CRYPT_CERTACTION_TYPE action );
int caIssueCRL( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iCryptCRL,
				const CRYPT_CONTEXT caKey );

/* Prototypes for routines in ca_misc.c */

int updateCertLog( DBMS_INFO *dbmsInfo, const int action, const char *certID, 
				   const char *reqCertID, const char *subjCertID, 
				   const void *data, const int dataLength, 
				   const DBMS_UPDATE_TYPE updateType );
int updateCertErrorLog( DBMS_INFO *dbmsInfo, const int errorStatus,
						const char *errorString, const char *certID,
						const char *reqCertID, const char *subjCertID,
						const void *data, const int dataLength );
int updateCertErrorLogMsg( DBMS_INFO *dbmsInfo, const int errorStatus,
						   const char *errorString );
int caGetIssuingUser( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iPkiUser,
					  const char *initialCertID, 
					  const int initialCertIDlength );
int initDBMSCA( KEYSET_INFO *keysetInfo );
