/****************************************************************************
*																			*
*					  cryptlib Keyset Interface Header File 				*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#ifndef _KEYSET_DEFINED

#define _KEYSET_DEFINED

/* Various include files needed by the DBMS libraries.  To enable the code
   for a particular database interface, define USE_<database-type> (multiple
   database types can be defined, the required interface is selected at
   runtime).  Currently supported database types and operating systems are:

	USE_ODBC		Generic ODBC (always enabled under Windows)
	USE_MYSQL		MySQL
	USE_ORACLE		Oracle
	USE_POSTGRES	PostgreSQL
	USE_LDAP		LDAP (always enabled under Windows)
	USE_HTTP		HTTP (always enabled under Unix and Windows) */

#include <time.h>
#ifdef USE_ODBC
  #if defined( __WIN32__ ) && !defined( WIN32 )
	/* As part of the ever-changing way of identifying Win32, Microsoft 
	   changed the predefined constant from WIN32 to _WIN32 in VC++ 2.1.  
	   However the ODBC header files still expect to find WIN32, and if this 
	   isn't defined will use the default (i.e. C) calling convention 
	   instead of the Pascal convention which is actually used by the ODBC 
	   functions.  This means that both the caller and the callee clean up 
	   the stack, so that for each ODBC call the stack creeps upwards by a 
	   few bytes until eventually the local variables and/or return address 
	   get trashed.  This problem is usually hidden by the fact that 
	   something else defines WIN32 so everything works OK, but the October 
	   1997 development platform upgrade changes this so that compiling the 
	   code after this update is installed breaks things.

	   To avoid this problem, we define WIN32 if it isn't defined, which
	   ensures that the ODBC header files work properly */
	#define WIN32
  #endif /* __WIN32__ && !WIN32 */
  #if defined( __BORLANDC__ )
	#include <mfc/sqltypes.h>
  #else
	#ifdef __WINDOWS__
	  /* UnixODBC defines its own version of various Windows types, if we're
		 building under Windows we have to disable this.  The UnixODBC 
		 headers have a guard ALLREADY_HAVE_WINDOWS_TYPE (sic) but this is
		 all-or-nothing, disabling the defining of Windows *and* SQL types.
		 Defining the guard value fixes most compile problems, but in order
		 to build it the commented-out typedefs also need to be defined.
		 These are already defined in the standard (Windows) sqltypes.h so
		 their use needs to be manually enabled for UnixODBC under Windows
		 (which is unlikely to occur, given that it's a Unix-only driver) */
	  #define ALLREADY_HAVE_WINDOWS_TYPE
	  #if 0
	  typedef signed short RETCODE;
	  typedef short int SWORD;
	  typedef long int SDWORD;
	  typedef signed char SQLSCHAR;
	  typedef HWND SQLHWND;
	  #endif /* 0 */
	#endif /* __WINDOWS__ */
	#include <sql.h>
	#include <sqlext.h>
  #endif /* Borland vs.everything else */
#endif /* __WINDOWS__ */
#ifdef USE_MYSQL
  #include <mysql.h>
#endif /* USE_MYSQL */
#ifdef USE_ORACLE
  #include "oratypes.h"
  #include "ocidfn.h"
  #include "ociapr.h"
  /* oratypes.h defines 'boolean' itself so we undefine it again here to 
     avoid clashes with cryptlib variables of that name */
  #undef boolean
#endif /* USE_ORACLE */
#ifdef USE_POSTGRES
  #include "libpq-fe.h"
#endif /* USE_POSTGRES */
#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined( INC_CHILD )
	#include "../misc/stream.h"
  #else
	#include "misc/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* The maximum size of a cert in binary and base64-encoded form */

#define MAX_CERT_SIZE				1536
#define MAX_ENCODED_CERT_SIZE		2048	/* base64-encoded */

/* Keyset information flags */

#define KEYSET_OPEN			0x01	/* Keyset is open */
#define KEYSET_EMPTY		0x02	/* Keyset is empty */
#define KEYSET_DIRTY		0x04	/* Keyset data has been changed */
#define KEYSET_STREAM_OPEN	0x08	/* Underlying file stream is open */

/* Some older compilers don't yet have the ANSI FILENAME_MAX define so we
   define a reasonable value here (the length is checked when we open the
   keyset so there's no chance it'll overflow even if the OS path limit is
   higher than what's defined here) */

#ifndef FILENAME_MAX
  #if defined( __MSDOS16__ )
	#define FILENAME_MAX	80
  #elif defined( __hpux )
	#include <sys/param.h>	/* HPUX's stdio.h defines this to be 14 (!!) */
	#define FILENAME_MAX	MAXPATHLEN
  #else
	#define FILENAME_MAX	256
  #endif /* __MSDOS16__ */
#endif /* FILENAME_MAX */

/* The precise type of the key file we're working with.  This is used for
   type checking to make sure we don't try to find private keys in a
   collection of public-key certificates or whatever */

typedef enum {
	KEYSET_SUBTYPE_NONE,			/* Unknown */
	KEYSET_SUBTYPE_ERROR,			/* Bad keyset format */
	KEYSET_SUBTYPE_PGP_PUBLIC,		/* PGP public keyring */
	KEYSET_SUBTYPE_PGP_PRIVATE,		/* PGP private keyring */
	KEYSET_SUBTYPE_PKCS12,			/* PKCS #12 key mess */
	KEYSET_SUBTYPE_PKCS15			/* PKCS #15 keys */
	} KEYSET_SUBTYPE;

/* When perform a DBMS transaction there are several variations on the basic
   operation type.  The following values tell performQuery() and
   performUpdate() which type of operation to perform */

typedef enum {
	DBMS_QUERY_NORMAL,				/* Standard data fetch */
	DBMS_QUERY_CHECK,				/* Check-type fetch, don't fetch data */
	DBMS_QUERY_START,				/* Begin an ongoing query */
	DBMS_QUERY_CONTINUE,			/* Continue an ongoing query */
	DBMS_QUERY_CANCEL				/* Cancel ongoing query */
	} DBMS_QUERY_TYPE;

typedef enum {
	DBMS_UPDATE_NORMAL,				/* Standard update */
	DBMS_UPDATE_BEGIN,				/* Begin a transaction */
	DBMS_UPDATE_CONTINUE,			/* Continue an ongoing transaction */
	DBMS_UPDATE_COMMIT,				/* Commit a transaction */
	DBMS_UPDATE_ABORT				/* Abort a transaction */
	} DBMS_UPDATE_TYPE;

/* Database state information maintained by the database backed-specific
   code */

typedef struct {
	/* DBMS status information */
	BOOLEAN needsUpdate;			/* Whether key DBX needs to be committed */
	BOOLEAN hasBinaryBlobs;			/* Whether DBMS supports binary blobs */
	char blobName[ 64 ];			/* Name of blob data type */

	/* Pointers to error information returned by the database.  The data
	   itself is stored in a common location in the KEYSET_INFO struct */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];

	/* Database-specific information */
  #ifdef USE_ODBC
	/* ODBC access information */
	HENV hEnv;						/* Environment handle */
	HDBC hDbc;						/* Connection handle */
	HSTMT hStmt;					/* Statement handle */
	SWORD blobType;					/* SQL type of blob data type */
	SDWORD cbBlobLength;			/* Length of key (blob) data */
	char dateTimeName[ 64 ];		/* Name of datetime data type */
	char escapeChar;				/* SQL query escape char */
  #endif /* USE_ODBC */
  #ifdef USE_MYSQL
	MYSQL *connection;				/* Connection handle */
	MYSQL_RES *result;				/* Result set */
  #endif /* USE_MYSQL */
  #ifdef USE_ORACLE
	Lda_Def lda;					/* Logon data area */
	ub1 hda[ 256 ];					/* Host data area */
	Cda_Def cda;					/* Cursor data area */
  #endif /* USE_ORACLE */
  #ifdef USE_POSTGRES
	PGconn *pgConnection;			/* Connection handle */
	PGresult *pgResult;				/* Query result handle */
  #endif /* USE_POSTGRES */
  #ifdef USE_TCP
	STREAM stream;					/* Network I/O stream */
  #endif /* USE_TCP */
	} DBMS_STATE_INFO;

/* The internal fields in a keyset that hold data for the various keyset
   types.   These are implemented as a union to allow keyset-type-specific
   information to be passed to lower-level routines without having to have
   an entire keyset record present, and as a convenient side-effect to
   conserve memory with some of the more data-intensive types such as
   database keysets.  In addition the structures provide a convenient way to
   group the keyset type-specific parameters */

typedef enum { KEYSET_NONE, KEYSET_FILE, KEYSET_DBMS, KEYSET_LDAP,
			   KEYSET_HTTP } KEYSET_TYPE;

struct KI;	/* Forward declaration for argument to function pointers */

typedef struct {
	/* The I/O stream and file name */
	STREAM stream;					/* I/O stream for key file */
	char fileName[ FILENAME_MAX ];	/* Name of key file */
	} FILE_INFO;

typedef struct DI {
	/* DBMS status information */
	int flags;						/* General status flags */

	/* For database types that can use binary blobs we need to bind the
	   locations of variables and use placeholders in the SQL text rather
	   than passing the data as part of the SQL command.  We can't leave this
	   on the stack since it can be referenced by the backend an arbitrary 
	   amount of time after we initiate the update, so we copy it to the
	   following staging area before we pass control to the backend */
	char boundData[ MAX_ENCODED_CERT_SIZE ];

	/* The data being sent to the backend can be communicated over a variety
	   of channels, the following function pointer points to the appropriate
	   dispatch function and the state information contains the state data
	   needed for the communications channel */
	void ( *dispatchFunction )( void *stateInfo, BYTE *buffer );
	void *stateInfo;

	/* Pointers to database-specific keyset access methods */
	int ( *certMgmtFunction )( struct KI *keysetInfo, 
							   CRYPT_CERTIFICATE *iCryptCert,
							   const CRYPT_CERTIFICATE caKey,
							   const CRYPT_CERTIFICATE request,
							   const CRYPT_CERTACTION_TYPE action );

	/* Database backend access functions.  These use the dispatch function 
	   above to communicate with the backend */
	int ( *openDatabaseFunction )( struct DI *dbmsInfo, const char *name,
								   const int options );
	void ( *closeDatabaseFunction )( struct DI *dbmsInfo );
	int ( *performUpdateFunction )( struct DI *dbmsInfo, const char *command,
									const void *boundData, 
									const int boundDataLength,
									const time_t boundDate,
									const DBMS_UPDATE_TYPE updateType );
	int ( *performStaticUpdateFunction )( struct DI *dbmsInfo, 
										  const char *command );
	int ( *performQueryFunction )( struct DI *dbmsInfo, const char *command,
								   char *data, int *dataLength, 
								   const time_t date,
								   const DBMS_QUERY_TYPE queryType );
	int ( *performStaticQueryFunction )( struct DI *dbmsInfo, 
										 const char *command,
										 const DBMS_QUERY_TYPE queryType );

	/* Last-error information returned from lower-level code */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];
	} DBMS_INFO;

typedef struct {
	/* The I/O stream */
	STREAM stream;					/* I/O stream for HTTP read */

	/* An HTTP fetch differs from the other types of read in that it can
	   return data in multiple chunks depending on how much comes over the
	   net at once.  Because of this we need to track what's come in, and
	   also allocate more buffer space on demand if required.  The following
	   variables handle the on-demand reallocation of buffer space */
	int bufPos;						/* Current position in buffer */

	/* Last-error information returned from lower-level code */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];
	} HTTP_INFO;

typedef struct {
	/* LDAP status information */
	BOOLEAN queryInProgress;		/* Whether ongoing query is in progress */

	/* LDAP access information */
	void *ld;						/* LDAP connection information */
	void *result;					/* State information for ongoing queries */

	/* The names of the object class and various attributes.  These are
	   stored as part of the keyset context since they may be user-defined or
	   the library-wide definition may change over time */
	char nameObjectClass[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of object class */
	char nameFilter[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of query filter */
	char nameCACert[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of CA cert attribute */
	char nameCert[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of cert attribute */
	char nameCRL[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Name of CRL attribute */
	char nameEmail[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of email addr.attr.*/
	CRYPT_CERTTYPE_TYPE objectType;				/* Preferred obj.type to fetch */

	/* When storing a cert we need the certificate DN, email address,
	   and cert expiry date */
	char C[ CRYPT_MAX_TEXTSIZE + 1 ], SP[ CRYPT_MAX_TEXTSIZE + 1 ],
		L[ CRYPT_MAX_TEXTSIZE + 1 ], O[ CRYPT_MAX_TEXTSIZE + 1 ],
		OU[ CRYPT_MAX_TEXTSIZE + 1 ], CN[ CRYPT_MAX_TEXTSIZE + 1 ];
	char email[ CRYPT_MAX_TEXTSIZE + 1 ];
	time_t date;

	/* Last-error information returned from lower-level code */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];
	} LDAP_INFO;

/* Defines to make access to the union fields less messy */

#define keysetFile		keysetInfo.fileInfo
#define keysetDBMS		keysetInfo.dbmsInfo
#define keysetHTTP		keysetInfo.httpInfo
#define keysetLDAP		keysetInfo.ldapInfo

/* The structure that stores information on a keyset */

typedef struct KI {
	/* General keyset information */
	KEYSET_TYPE type;				/* Keyset type (native, PGP, X.509, etc) */
	KEYSET_SUBTYPE subType;			/* Keyset subtype (public, private, etc) */
	CRYPT_KEYOPT_TYPE options;		/* Keyset option */
	int flags;						/* Keyset information flags */

	/* Keyset type-specific information */
	union {
		FILE_INFO *fileInfo;
		DBMS_INFO *dbmsInfo;
		HTTP_INFO *httpInfo;
		LDAP_INFO *ldapInfo;
		} keysetInfo;

	/* Pointers to keyset access methods */
	int ( *initFunction )( struct KI *keysetInfo, const char *name,
						   const CRYPT_KEYOPT_TYPE options );
	void ( *shutdownFunction )( struct KI *keysetInfo );
	int ( *getAttributeFunction )( struct KI *keysetInfo, void *data,
								   const CRYPT_ATTRIBUTE_TYPE type );
	int ( *setAttributeFunction )( struct KI *keysetInfo, const void *data,
								   const CRYPT_ATTRIBUTE_TYPE type );
	int ( *getItemFunction )( struct KI *keysetInfo,
							  CRYPT_HANDLE *iCryptHandle,
							  const KEYMGMT_ITEM_TYPE itemType,
							  const CRYPT_KEYID_TYPE keyIDtype,
							  const void *keyID,  const int keyIDlength,
							  void *auxInfo, int *auxInfoLength,
							  const int flags );
	int ( *setItemFunction )( struct KI *deviceInfo,
							  const CRYPT_HANDLE iCryptHandle,
							  const KEYMGMT_ITEM_TYPE itemType,
							  const char *password, const int passwordLength,
							  const int flags );
	int ( *deleteItemFunction )( struct KI *keysetInfo,
								 const KEYMGMT_ITEM_TYPE itemType,
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength );
	int ( *getFirstItemFunction )( struct KI *keysetInfo,
								   CRYPT_CERTIFICATE *iCertificate,
								   int *stateInfo,
								   const CRYPT_KEYID_TYPE keyIDtype,
								   const void *keyID, const int keyIDlength,
								   const KEYMGMT_ITEM_TYPE itemType,
								   const int options );
	int ( *getNextItemFunction )( struct KI *keysetInfo,
								  CRYPT_CERTIFICATE *iCertificate,
								  int *stateInfo, const int options );
	BOOLEAN ( *isBusyFunction )( struct KI *keysetInfo );

	/* Some keysets require keyset-type-specific data storage which is
	   managed via the following variables */
	void *keyData;					/* Keyset data buffer */
	int keyDataSize;				/* Buffer size */

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
	} KEYSET_INFO;

/* Prototypes for various utility functions in cryptdbx.c.  retExt() returns 
   after setting extended error information for the keyset.  We use a macro 
   to make it match the standard return statement, the slightly unusual form 
   is required to handle the fact that the helper function is a varargs
   function */

int retExtFnKeyset( KEYSET_INFO *keysetInfoPtr, const int status, 
					const char *format, ... );
#define retExt	return retExtFnKeyset

/* Prototypes for keyset mapping functions */

#ifdef USE_ODBC
  int dbxInitODBC( void );
  void dbxEndODBC( void );
#else
  #define dbxInitODBC()						CRYPT_OK
  #define dbxEndODBC()
#endif /* USE_ODBC */
#ifdef USE_DBMS
  int setAccessMethodDBMS( KEYSET_INFO *keysetInfo,
						   const CRYPT_KEYSET_TYPE type );
#else
  #define setAccessMethodDBMS( x, y )		CRYPT_ARGERROR_NUM1
#endif /* USE_DBMS */
#ifdef USE_HTTP
  int setAccessMethodHTTP( KEYSET_INFO *keysetInfo );
#else
  #define setAccessMethodHTTP( x )			CRYPT_ARGERROR_NUM1
#endif /* USE_HTTP */
#ifdef USE_LDAP
  int dbxInitLDAP( void );
  void dbxEndLDAP( void );
  int setAccessMethodLDAP( KEYSET_INFO *keysetInfo );
#else
  #define dbxInitLDAP()						CRYPT_OK
  #define dbxEndLDAP()
  #define setAccessMethodLDAP( x )			CRYPT_ARGERROR_NUM1
#endif /* USE_LDAP */
#ifdef USE_PGPKEYS
  int setAccessMethodPGPPublic( KEYSET_INFO *keysetInfo );
  int setAccessMethodPGPPrivate( KEYSET_INFO *keysetInfo );
#else
  #define setAccessMethodPGPPublic( x )		CRYPT_ARGERROR_NUM1
  #define setAccessMethodPGPPrivate( x )	CRYPT_ARGERROR_NUM1
#endif /* USE_PGPKEYS */
#ifdef USE_PKCS12
  int setAccessMethodPKCS12( KEYSET_INFO *keysetInfo );
#else
  #define setAccessMethodPKCS12( x )		CRYPT_ARGERROR_NUM1
#endif /* PKCS #12 */
#ifdef USE_PKCS15
  int setAccessMethodPKCS15( KEYSET_INFO *keysetInfo );
#else
  #define setAccessMethodPKCS15( x )		CRYPT_ARGERROR_NUM1
#endif /* PKCS #15 */
#ifdef USE_PKCS12
  #define isWriteableFileKeyset( type ) \
		  ( ( type ) == KEYSET_SUBTYPE_PKCS12 || \
			( type ) == KEYSET_SUBTYPE_PKCS15 )
#else
  #define isWriteableFileKeyset( type ) \
		  ( ( type ) == KEYSET_SUBTYPE_PKCS15 )
#endif /* Writeable keyset subtypes */
#endif /* _KEYSET_DEFINED */
