/****************************************************************************
*																			*
*						 cryptlib ODBC Mapping Routines						*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "dbxdbx.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
  #include "dbxdbx.h"
#else
  #include "crypt.h"
  #include "keysets/keyset.h"
  #include "keyset/dbxdbx.h"
#endif /* Compiler-specific includes */

/* SQLError() returns error information at various levels and is rather
   unstable in its handling of input parameters, for example with some Win16 
   drivers if you pass it a valid hstmt then it may GPF after some calls so 
   you need to force a NULL hstmt.  The following values define the levels 
   of handle that we pass in in order for SQLError() to work as advertised */

#define SQL_ERRLVL_0	0
#define SQL_ERRLVL_1	1
#define SQL_ERRLVL_2	2

#ifdef USE_ODBC

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

#ifdef DYNAMIC_LOAD

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on some
   systems.

   MSDN updates from late 2000 defined SQLROWCOUNT themselves (which could be
   fixed by undefining it), however after late 2002 the value was typedef'd,
   requring all sorts of extra trickery to handle the different cases.  
   Because of this this particular function is typedef'd with a _FN suffix 
   to reduce problems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hODBC = NULL_HINSTANCE;

typedef RETCODE ( SQL_API *SQLALLOCENV )( HENV FAR *phenv );
typedef RETCODE ( SQL_API *SQLALLOCCONNECT )( HENV henv, HDBC FAR *phdbc );
typedef RETCODE ( SQL_API *SQLALLOCSTMT )( HDBC hdbc, HSTMT FAR *phstmt );
typedef RETCODE ( SQL_API *SQLBINDPARAMETER )( HSTMT hstmt, UWORD ipar,
				  SWORD fParamType, SWORD fCType, SWORD fSqlType,
				  UDWORD cbColDef, SWORD ibScale, PTR rgbValue,
				  SDWORD cbValueMax, SDWORD FAR *pcbValue );
typedef RETCODE ( SQL_API *SQLCANCEL )( HSTMT hstmt );
typedef RETCODE ( SQL_API *SQLCONNECT )( HDBC hdbc, UCHAR FAR *szDSN,
				  SWORD cdDSN, UCHAR FAR *szUID, SWORD cbUID,
				  UCHAR FAR *szAuthStr, SWORD cbAuthStr );
typedef RETCODE ( SQL_API *SQLDISCONNECT )( HDBC hdbc );
typedef RETCODE ( SQL_API *SQLERROR )( HENV henv, HDBC hdbc, HSTMT hstmt,
				  UCHAR FAR *szSqlState, SDWORD FAR *pfNativeError,
				  UCHAR FAR *szErrorMsg, SWORD cbErrorMsgMax,
				  SWORD FAR *pcbErrorMsg );
typedef RETCODE ( SQL_API *SQLEXECDIRECT )( HSTMT hstmt, UCHAR FAR *szSqlStr,
				  SDWORD cbSqlStr );
typedef RETCODE ( SQL_API *SQLEXECUTE )( HSTMT hstmt );
typedef RETCODE ( SQL_API *SQLFETCH )( HSTMT hstmt );
typedef RETCODE ( SQL_API *SQLFREECONNECT )( HDBC hdbc );
typedef RETCODE ( SQL_API *SQLFREEENV )( HENV henv );
typedef RETCODE ( SQL_API *SQLFREESTMT )( HSTMT hstmt, UWORD fOption );
typedef RETCODE ( SQL_API *SQLGETDATA )( HSTMT hstmt, UWORD icol,
				  SWORD fCType, PTR rgbValue, SDWORD cbValueMax,
				  SDWORD FAR *pcbValue );
typedef RETCODE ( SQL_API *SQLGETINFO )( HDBC hdbc, UWORD fInfoType,
				  PTR rgbInfoValue, SWORD cbInfoValueMax,
				  SWORD FAR *pcbInfoValue );
typedef RETCODE ( SQL_API *SQLGETTYPEINFO )( HSTMT hstmt, SWORD fSqlType );
typedef RETCODE ( SQL_API *SQLPARAMDATA )( HSTMT hstmt, PTR FAR *prgbValue );
typedef RETCODE ( SQL_API *SQLPREPARE )( HSTMT hstmt, UCHAR FAR *szSqlStr,
				  SDWORD cbSqlStr );
typedef RETCODE ( SQL_API *SQLPUTDATA )( HSTMT hstmt, PTR rgbValue,
				  SDWORD cbValue );
typedef RETCODE ( SQL_API *SQLROWCOUNT_FN )( HSTMT hstmt, SDWORD *cbRowCount );
typedef RETCODE ( SQL_API *SQLSETCONNECTOPTION )( HDBC hdbc, UWORD fOption,
				  UDWORD vParam );
typedef RETCODE ( SQL_API *SQLSETSTMTOPTION )( HSTMT hstmt, UWORD fOption,
				  UDWORD vParam );
typedef RETCODE ( SQL_API *SQLTRANSACT )( HENV henv, HDBC hdbc, UWORD fType );
static SQLALLOCCONNECT pSQLAllocConnect = NULL;
static SQLALLOCENV pSQLAllocEnv = NULL;
static SQLALLOCSTMT pSQLAllocStmt = NULL;
static SQLBINDPARAMETER pSQLBindParameter = NULL;
static SQLCANCEL pSQLCancel = NULL;
static SQLCONNECT pSQLConnect = NULL;
static SQLDISCONNECT pSQLDisconnect = NULL;
static SQLERROR pSQLError = NULL;
static SQLEXECDIRECT pSQLExecDirect = NULL;
static SQLEXECUTE pSQLExecute = NULL;
static SQLFETCH pSQLFetch = NULL;
static SQLFREECONNECT pSQLFreeConnect = NULL;
static SQLFREEENV pSQLFreeEnv = NULL;
static SQLFREESTMT pSQLFreeStmt = NULL;
static SQLGETDATA pSQLGetData = NULL;
static SQLGETINFO pSQLGetInfo = NULL;
static SQLGETTYPEINFO pSQLGetTypeInfo = NULL;
static SQLPARAMDATA pSQLParamData = NULL;
static SQLPREPARE pSQLPrepare = NULL;
static SQLPUTDATA pSQLPutData = NULL;
static SQLROWCOUNT_FN pSQLRowCount = NULL;
static SQLSETCONNECTOPTION pSQLSetConnectOption = NULL;
static SQLSETSTMTOPTION pSQLSetStmtOption = NULL;
static SQLTRANSACT pSQLTransact = NULL;

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define SQLAllocConnect			pSQLAllocConnect
#define SQLAllocEnv				pSQLAllocEnv
#define SQLAllocStmt			pSQLAllocStmt
#define SQLBindParameter		pSQLBindParameter
#define SQLCancel				pSQLCancel
#define SQLConnect				pSQLConnect
#define SQLDisconnect			pSQLDisconnect
#define SQLError				pSQLError
#define SQLExecDirect			pSQLExecDirect
#define SQLExecute				pSQLExecute
#define SQLFetch				pSQLFetch
#define SQLFreeConnect			pSQLFreeConnect
#define SQLFreeEnv				pSQLFreeEnv
#define SQLFreeStmt				pSQLFreeStmt
#define SQLGetData				pSQLGetData
#define SQLGetInfo				pSQLGetInfo
#define SQLGetTypeInfo			pSQLGetTypeInfo
#define SQLParamData			pSQLParamData
#define SQLPrepare				pSQLPrepare
#define SQLPutData				pSQLPutData
#define SQLRowCount				pSQLRowCount
#define SQLSetConnectOption		pSQLSetConnectOption
#define SQLSetStmtOption		pSQLSetStmtOption
#define SQLTransact				pSQLTransact

/* Depending on whether we're running under Win16 or Win32 we load the ODBC
   driver under a different name */

#ifdef __WIN16__
  #define ODBC_LIBNAME	"ODBC.DLL"
#else
  #define ODBC_LIBNAME	"ODBC32.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary DBMS libraries */

int dbxInitODBC( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */

	/* If the ODBC module is already linked in, don't do anything */
	if( hODBC != NULL_HINSTANCE )
		return( CRYPT_OK );

	/* Obtain a handle to the module containing the ODBC functions */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hODBC = LoadLibrary( ODBC_LIBNAME );
	SetErrorMode( errorMode );
	if( hODBC < HINSTANCE_ERROR )
		{
		hODBC = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}
#else
	if( ( hODBC = LoadLibrary( ODBC_LIBNAME ) ) == NULL_HINSTANCE )
		return( CRYPT_ERROR );
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pSQLAllocConnect = ( SQLALLOCCONNECT ) GetProcAddress( hODBC, "SQLAllocConnect" );
	pSQLAllocEnv = ( SQLALLOCENV ) GetProcAddress( hODBC, "SQLAllocEnv" );
	pSQLAllocStmt = ( SQLALLOCSTMT ) GetProcAddress( hODBC, "SQLAllocStmt" );
	pSQLBindParameter = ( SQLBINDPARAMETER ) GetProcAddress( hODBC, "SQLBindParameter" );
	pSQLCancel = ( SQLCANCEL ) GetProcAddress( hODBC, "SQLCancel" );
	pSQLConnect = ( SQLCONNECT ) GetProcAddress( hODBC, "SQLConnect" );
	pSQLDisconnect = ( SQLDISCONNECT ) GetProcAddress( hODBC, "SQLDisconnect" );
	pSQLError = ( SQLERROR ) GetProcAddress( hODBC, "SQLError" );
	pSQLExecDirect = ( SQLEXECDIRECT ) GetProcAddress( hODBC, "SQLExecDirect" );
	pSQLExecute = ( SQLEXECUTE ) GetProcAddress( hODBC, "SQLExecute" );
	pSQLFetch = ( SQLFETCH ) GetProcAddress( hODBC, "SQLFetch" );
	pSQLFreeConnect = ( SQLFREECONNECT ) GetProcAddress( hODBC, "SQLFreeConnect" );
	pSQLFreeEnv = ( SQLFREEENV ) GetProcAddress( hODBC, "SQLFreeEnv" );
	pSQLFreeStmt = ( SQLFREESTMT ) GetProcAddress( hODBC, "SQLFreeStmt" );
	pSQLGetData = ( SQLGETDATA ) GetProcAddress( hODBC, "SQLGetData" );
	pSQLGetInfo = ( SQLGETINFO ) GetProcAddress( hODBC, "SQLGetInfo" );
	pSQLGetTypeInfo = ( SQLGETTYPEINFO ) GetProcAddress( hODBC, "SQLGetTypeInfo" );
	pSQLParamData = ( SQLPARAMDATA ) GetProcAddress( hODBC, "SQLParamData" );
	pSQLPrepare = ( SQLPREPARE ) GetProcAddress( hODBC, "SQLPrepare" );
	pSQLPutData = ( SQLPUTDATA ) GetProcAddress( hODBC, "SQLPutData" );
	pSQLRowCount = ( SQLROWCOUNT_FN ) GetProcAddress( hODBC, "SQLRowCount" );
	pSQLSetConnectOption = ( SQLSETCONNECTOPTION ) GetProcAddress( hODBC, "SQLSetConnectOption" );
	pSQLSetStmtOption = ( SQLSETSTMTOPTION ) GetProcAddress( hODBC, "SQLSetStmtOption" );
	pSQLTransact = ( SQLTRANSACT ) GetProcAddress( hODBC, "SQLTransact" );

	/* Make sure that we got valid pointers for every ODBC function */
	if( pSQLAllocConnect == NULL || pSQLAllocEnv == NULL ||
		pSQLAllocStmt == NULL || pSQLBindParameter == NULL ||
		pSQLCancel == NULL || pSQLConnect == NULL ||
		pSQLDisconnect == NULL || pSQLError == NULL ||
		pSQLExecDirect == NULL || pSQLExecute == NULL ||
		pSQLFetch == NULL || pSQLFreeConnect == NULL ||
		pSQLFreeEnv == NULL || pSQLFreeStmt == NULL ||
		pSQLGetData == NULL || pSQLGetInfo == NULL ||
		pSQLGetTypeInfo == NULL || pSQLParamData == NULL ||
		pSQLPrepare == NULL || pSQLPutData == NULL ||
		pSQLSetConnectOption == NULL || pSQLSetStmtOption == NULL ||
		pSQLTransact == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hODBC );
		hODBC = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

void dbxEndODBC( void )
	{
	if( hODBC != NULL_HINSTANCE )
		FreeLibrary( hODBC );
	hODBC = NULL_HINSTANCE;
	}
#else

int dbxInitODBC( void )
	{
	return( CRYPT_OK );
	}

void dbxEndODBC( void )
	{
	}
#endif /* DYNAMIC_LOAD */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Get information on an ODBC error */

static int getErrorInfo( DBMS_STATE_INFO *dbmsInfo, const int errorLevel,
						 const int defaultStatus )
	{
	HDBC hdbc = ( errorLevel < 1 ) ? SQL_NULL_HDBC : dbmsInfo->hDbc;
	HDBC hstmt = ( errorLevel < 2 ) ? SQL_NULL_HSTMT : dbmsInfo->hStmt;
	char altErrorMessage[ MAX_ERRMSG_SIZE ];
	char szSqlState[ SQL_SQLSTATE_SIZE ], szAltSqlState[ SQL_SQLSTATE_SIZE ];
	SDWORD dwNativeError = 0, dwAltNativeError = 0;
	SWORD dummy;
	RETCODE retCode;

	/* Get the initial ODBC error info.  We pre-set the native error codes
	   to set because they sometimes aren't set by SQLError() */
	retCode = SQLError( dbmsInfo->hEnv, hdbc, hstmt, szSqlState,
						&dwNativeError, dbmsInfo->errorMessage,
						MAX_ERRMSG_SIZE - 1, &dummy );
	dbmsInfo->errorCode = ( int ) dwNativeError;	/* Usually 0 */

	/* Work around a bug in ODBC 2.0 drivers (still present on older NT 4
	   machines) in which the primary error is some bizarre nonsense value
	   and the actual error is present at the second level */
	retCode = SQLError( dbmsInfo->hEnv, hdbc, hstmt, szAltSqlState,
						&dwAltNativeError, altErrorMessage,
						MAX_ERRMSG_SIZE - 1, &dummy );
	if( !strncmp( szSqlState, "01004", 5 ) )
		{
		memcpy( szSqlState, szAltSqlState, SQL_SQLSTATE_SIZE );
		strcpy( dbmsInfo->errorMessage, altErrorMessage );
		}

	/* Some of the information returned by SQLError() is pretty odd.  It
	   usually returns an ANSI SQL2 error state in SQLSTATE, but also returns
	   a native error code in NativeError.  However the NativeError codes
	   aren't documented anywhere, so we rely on SQLSTATE having a useful
	   value.  	We can also get SQL_NO_DATA_FOUND with SQLSTATE set to
	   "00000" and the error message string empty */
	if( !strncmp( szSqlState, "S0002", 5 ) ||	/* ODBC 2.x */
		!strncmp( szSqlState, "42S02", 5 ) ||	/* ODBC 3.x */
		( !strncmp( szSqlState, "00000", 5 ) && retCode == SQL_NO_DATA_FOUND ) )
		{
		/* Make sure that the caller gets a sensible error message if they
		   try to examine the extended error information */
		if( !*dbmsInfo->errorMessage )
			strcpy( dbmsInfo->errorMessage, "No data found." );
		return( CRYPT_ERROR_NOTFOUND );
		}

	/* When we're trying to create a new keyset, there may already be one
	   present giving an S0001 (table already exists) or S0011 (index
	   already exists) error .  We could check for the table by doing a
	   dummy read, but it's easier to just try the update anyway and convert
	   the error code to the correct value here if there's a problem */
	if( !strncmp( szSqlState, "S0001", 5 ) ||
		!strncmp( szSqlState, "S0011", 5 ) ||	/* ODBC 2.x */
		!strncmp( szSqlState, "42S01", 5 ) ||
		!strncmp( szSqlState, "42S11", 5 ) )	/* ODBX 3.x */
		return( CRYPT_ERROR_DUPLICATE );

	/* This one is a bit odd: An integrity constraint violation occurred,
	   which means (among other things) that an attempt was made to write a
	   duplicate value to a column constrained to contain unique values.  It
	   can also include things like writing a NULL value to a column
	   constrained to be NOT NULL, but this wouldn't normally happen so we
	   can convert this one to a duplicate data error */
	if( !strncmp( szSqlState, "23000", 5 ) )
		return( CRYPT_ERROR_DUPLICATE );

	return( defaultStatus );
	}

/* Some MS database engines uses nonstandard SQL for primary keys.  Instead
   of allowing a simple PRIMARY KEY qualifier, they require that the use of
   a primary key to be given as constraint on a column, which also involves
   creating an index on that column.  In theory we could rewrite the primary
   key qualifier to create a fixed-name index using the constraint notation,
   however Access and SQL Server go even further and create an implied unique
   index for the key, making it both useless for its intended purpose
   (forcing clustering of identical entries) as well as rendering the table
   unusable (since it'll only allow a single value to be added).  Because of
   this we have to remove the PRIMARY KEY qualifier entirely.

   Detecting when this is necessary is tricky, it's required for Access, and
   SQL Server but not for Foxpro or (probably) any non-MS products, so we
   check for a DBMS name of "Access" or "SQL Server" and remove it if we find
   either.  In addition if we find Access we fix up some other problems it
   has as well */

static void convertQuery( DBMS_STATE_INFO *dbmsInfo, char *query,
						  const char *command )
	{
	RETCODE retCode;
	SWORD bufLen;
	char *keywordPtr, buffer[ 128 ];

	assert( command != NULL );
	strcpy( query, command );

	/* If it's a CREATE TABLE command, rewrite the blob and date types to
	   the appropriate values for the database backend */
	if( !strncmp( command, "CREATE TABLE", 12 ) )
		{
		char *placeholderPtr;

		if( ( placeholderPtr = strstr( query, " BLOB" ) ) != NULL )
			{
			const int nameLen = strlen( dbmsInfo->blobName );

			/* Open up a gap and replace the blob name placeholder with the
			   actual blob name */
			memmove( placeholderPtr + 1 + nameLen, placeholderPtr + 5,
					 strlen( placeholderPtr + 5 ) + 1 );
			memcpy( placeholderPtr + 1, dbmsInfo->blobName, nameLen );
			}
		if( ( placeholderPtr = strstr( query, " DATETIME" ) ) != NULL )
			{
			const int nameLen = strlen( dbmsInfo->dateTimeName );

			/* Open up a gap and replace the date name placeholder with the
			   actual date name */
			memmove( placeholderPtr + 1 + nameLen, placeholderPtr + 9,
					 strlen( placeholderPtr + 9 ) + 1 );
			memcpy( placeholderPtr + 1, dbmsInfo->dateTimeName, nameLen );
			}
		}

	/* If it's not a CREATE TABLE command with a primary key or a
	   SELECT/DELETE with wildcards used, there's nothing to do */
	if( ( strncmp( query, "CREATE TABLE", 12 ) || \
		  ( keywordPtr = strstr( query, " PRIMARY KEY" ) ) == NULL ) && \
		( ( strncmp( query, "SELECT", 6 ) && strncmp( query, "DELETE", 6 ) ) || \
		  strstr( query, " LIKE " ) == NULL ) )
		return;

	/* It's a potential problem command, check for the presence of Access or
	   SQL Server */
	retCode = SQLGetInfo( dbmsInfo->hDbc, SQL_DBMS_NAME, buffer,
						  sizeof( buffer ), &bufLen );
	if( ( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO ) && \
		strCompare( buffer, "Access", 6 ) && \
		strCompare( buffer, "SQL Server", 10 ) )
		return;
	if( query[ 0 ] == 'C' )
		{
#if 0
		/* Rewrite the PRIMARY KEY qualifier as a constraint on the column.
		   We use the name 'PrimaryKey' since this is what Access uses by
		   default */
		memmove( keywordPtr + 33, keywordPtr + 12,
				 ( strlen( keywordPtr ) - 12 ) + 1 );
		memcpy( keywordPtr, "CONSTRAINT PrimaryKey PRIMARY KEY", 33 );
#else
		/* Remove the PRIMARY KEY qualifier (the constraint mechanism is too
		   awkward to handle cleanly, see the comment at the start of this
		   function) */
		memmove( keywordPtr, keywordPtr + 12, strlen( keywordPtr + 12 ) + 1 );
#endif /* 0 */
		}
	else
		{
		/* Unlike everything else in the known universe, Access uses * and ?
		   instead of the standard SQL wildcards so if we find a LIKE ... %
		   we rewrite the % as a * */
		if( buffer[ 0 ] == 'A' && \
			( keywordPtr = strstr( query, " LIKE " ) ) != NULL )
			{
			int i;

			/* Search up to 5 characters ahead for a wildcard and replace it
			   with the one needed by Access if we find it */
			for( i = 7; i < 11 && keywordPtr[ i ]; i++ )
				if( keywordPtr[ i ] == '%' )
					keywordPtr[ i ] = '*';
			}
		}
	}

/* Get the name of the blob and date data type for this data source */

static int getDatatypeInfo( DBMS_STATE_INFO *dbmsInfo )
	{
	RETCODE retCode;
	SDWORD length;
	SWORD bufLen;
	char buffer[ 8 ];
	long count;

	SQLAllocStmt( dbmsInfo->hDbc, &dbmsInfo->hStmt );

	/* First we see whether the database supports long binary strings.  Most
	   of the newer ones that are likely to be used do */
	retCode = SQLGetTypeInfo( dbmsInfo->hStmt, SQL_LONGVARBINARY );
	if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
		{
		/* Get the results of the transaction.  If the database doesn't
		   support this, we'll get SQL_NO_DATA_FOUND (status 100) returned */
		retCode = SQLFetch( dbmsInfo->hStmt );
		if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
			{
			/* Get the type name and maximum possible field length.  We only
			   check the second return code since they both apply to the same
			   row */
			SQLGetData( dbmsInfo->hStmt, 1, SQL_C_CHAR,
						dbmsInfo->blobName, 64, &length );
			retCode = SQLGetData( dbmsInfo->hStmt, 3, SQL_C_LONG,
								  &count, sizeof( long ), &length );
			if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
				{
				dbmsInfo->hasBinaryBlobs = TRUE;
				dbmsInfo->blobType = SQL_LONGVARBINARY;
				}
			}
		else
			{
			/* The backend doesn't support binary blobs, get the name of the 
			   long char type for this data source */
			SQLFreeStmt( dbmsInfo->hStmt, SQL_CLOSE );
			retCode = SQLGetTypeInfo( dbmsInfo->hStmt, SQL_LONGVARCHAR );
			if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
				{
				/* Get the results of the transaction */
				retCode = SQLFetch( dbmsInfo->hStmt );
				if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
					{
					/* Get the type name and maximum possible field length.
					   We only check the second return code since they both
					   apply to the same row */
					SQLGetData( dbmsInfo->hStmt, 1, SQL_C_CHAR,
								dbmsInfo->blobName, 64, &length );
					retCode = SQLGetData( dbmsInfo->hStmt, 3, SQL_C_LONG,
										  &count, sizeof( long ), &length );
					dbmsInfo->blobType = SQL_LONGVARCHAR;
					}
				}
			}
		}

	/* If we couldn't get a blob type or the type is too short to use,
	   report it back as a database open failure */
	if( ( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO ) || \
		count < 4096 )
		{
		if( count >= 4096 )
			/* There was a problem, get more details */
			getErrorInfo( dbmsInfo, SQL_ERRLVL_0, CRYPT_ERROR_OPEN );
		SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
		return( CRYPT_ERROR_OPEN );
		}

	/* Now do the same thing for the date+time data type.  This changed from
	   SQL_TIMESTAMP in ODBC 2.x to SQL_TYPE_TIMESTAMP in ODBC 3.x, since 3.x
	   will be more common we try the 3.x version first and if that fails
	   fall back to 2.x */
	SQLFreeStmt( dbmsInfo->hStmt, SQL_CLOSE );
	retCode = SQLGetTypeInfo( dbmsInfo->hStmt, SQL_TYPE_TIMESTAMP );
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		retCode = SQLGetTypeInfo( dbmsInfo->hStmt, SQL_TIMESTAMP );
	if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
		{
		/* Fetch the results of the transaction and get the type name */
		retCode = SQLFetch( dbmsInfo->hStmt );
		if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
			retCode = SQLGetData( dbmsInfo->hStmt, 1, SQL_C_CHAR,
								  dbmsInfo->dateTimeName, 64, &length );
		}
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		getErrorInfo( dbmsInfo, SQL_ERRLVL_0, CRYPT_ERROR_OPEN );
		SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
		return( CRYPT_ERROR_OPEN );
		}

#if 0	/* Not needed since we always supply the length */
	retCode = SQLGetInfo( dbmsInfo->hDbc, SQL_NEED_LONG_DATA_LEN,
						  buffer, sizeof( buffer ), &bufLen );
	if( retCode != SQL_SUCCESS )
		dbmsInfo->needLongLength = TRUE;	/* Make a paranoid guess */
	else
		dbmsInfo->needLongLength = ( *buffer == 'Y' ) ? TRUE : FALSE;
#endif /* 0 */


	/* Finally, determine the escape char being used.  This is usually '\',
	   but it may have been changed for some reason */
	retCode = SQLGetInfo( dbmsInfo->hDbc, SQL_SEARCH_PATTERN_ESCAPE,
						  buffer, sizeof( buffer ), &bufLen );
	dbmsInfo->escapeChar = ( retCode == SQL_SUCCESS ) ? buffer[ 0 ] : '\\';

	SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
	dbmsInfo->hStmt = NULL;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Database Open/Close Routines					*
*																			*
****************************************************************************/

/* Close a previously-opened ODBC connection.  We have to have this before
   openDatabase() since it may be called by openDatabase() if the open
   process fails.  This is necessary because the complex ODBC open may
   require a fairly extensive cleanup afterwards */

static void closeDatabase( DBMS_STATE_INFO *dbmsInfo )
	{
	assert( isWritePtr( dbmsInfo, DBMS_STATE_INFO ) );

	/* Commit the transaction.  The default transaction mode for drivers 
	   that support SQLSetConnectOption() is auto-commit so the 
	   SQLTransact() call isn't strictly necessary, but we play it safe 
	   anyway */
	if( dbmsInfo->needsUpdate )
		{
		SQLTransact( dbmsInfo->hEnv, dbmsInfo->hDbc, SQL_COMMIT );
		dbmsInfo->needsUpdate = FALSE;
		}

	/* Clean up */
	SQLDisconnect( dbmsInfo->hDbc );
	SQLFreeConnect( dbmsInfo->hDbc );
	SQLFreeEnv( dbmsInfo->hEnv );
	dbmsInfo->hStmt = NULL;
	dbmsInfo->hDbc = NULL;
	dbmsInfo->hEnv = NULL;
	}

/* Open a connection to a data source using ODBC.  We don't check the return
   codes for many of the functions since the worst that can happen if they
   fail is that performance will be somewhat suboptimal.  In addition we
   don't allocate statement handles at this point since these are handled in
   various strange and peculiar ways by different ODBC drivers.  The main
   problem is that some drivers don't support mode than one hstmt per hdbc,
   some support only one active hstmt (an hstmt with results pending) per
   hdbc, and some support multiple active hstmt's per hdbc.  For this reason
   we use a strategy of allocating an hstmt, performing a transaction, and
   then immediately freeing it again afterwards */

static int openDatabase( DBMS_STATE_INFO *dbmsInfo, const char *name,
						 const int options, int *featureFlags )
	{
	DBMS_NAME_INFO nameInfo;
	SWORD userLen = 0, passwordLen = 0;
	RETCODE retCode;
	int status;

	assert( isWritePtr( dbmsInfo, DBMS_STATE_INFO ) );
	assert( isReadPtr( name, 2 ) );
	assert( isWritePtr( featureFlags, sizeof( int ) ) );

	/* Make sure that the driver is bound in */
	if( hODBC == NULL_HINSTANCE )
		return( CRYPT_ERROR_OPEN );

	/* Parse the data source into its individual components */
	status = dbmsParseName( &nameInfo, name, SQL_NTS );
	if( cryptStatusError( status ) )
		return( status );

	/* Allocate environment and connection handles */
	SQLAllocEnv( &dbmsInfo->hEnv );
	SQLAllocConnect( dbmsInfo->hEnv, &dbmsInfo->hDbc );

	/* Set the access mode to read-only if we can.  The default is R/W, but
	   setting it to read-only optimises transaction management */
	if( options == CRYPT_KEYOPT_READONLY )
		SQLSetConnectOption( dbmsInfo->hDbc, SQL_ACCESS_MODE,
							 SQL_MODE_READ_ONLY );

	/* Set the cursor type to forward-only (which should be the default).
	   Note that we're passing an SQLSetStmtOption() arg.to
	   SQLSetConnectOption(), which causes all stmt's allocated for this
	   connection to have the specified behaviour */
	SQLSetConnectOption( dbmsInfo->hDbc, SQL_CURSOR_TYPE,
						 SQL_CURSOR_FORWARD_ONLY );

	/* Turn off scanning for escape clauses in the SQL strings, which lets
	   the driver pass the string directly to the data source.  See the
	   comment for the previous call about the arg.being passed */
	SQLSetConnectOption( dbmsInfo->hDbc, SQL_NOSCAN, SQL_NOSCAN_ON );

	/* Once everything is set up the way we want it, try to connect to a data
	   source and allocate a statement handle */
	retCode = SQLConnect( dbmsInfo->hDbc, 
						  nameInfo.name, ( SQLSMALLINT ) nameInfo.nameLen,
						  nameInfo.user, ( SQLSMALLINT ) nameInfo.userLen,
						  nameInfo.password, ( SQLSMALLINT ) nameInfo.passwordLen );
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		getErrorInfo( dbmsInfo, SQL_ERRLVL_0, CRYPT_ERROR_OPEN );
		SQLFreeConnect( dbmsInfo->hDbc );
		SQLFreeEnv( dbmsInfo->hEnv );
		return( CRYPT_ERROR_OPEN );
		}

	/* Get various driver and source-specific information that we may need
	   later on */
	status = getDatatypeInfo( dbmsInfo );
	if( cryptStatusError( status ) )
		{
		closeDatabase( dbmsInfo );
		return( status );
		}
	*featureFlags = dbmsInfo->hasBinaryBlobs ? \
					DBMS_HAS_BINARYBLOBS : DBMS_HAS_NONE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Database Access Routines						*
*																			*
****************************************************************************/

/* Perform a transaction that updates the database without returning any
   data */

static int performUpdate( DBMS_STATE_INFO *dbmsInfo, const char *command,
						  const void *boundData, const int boundDataLength,
						  const time_t boundDate,
						  const DBMS_UPDATE_TYPE updateType )
	{
	TIMESTAMP_STRUCT timestampInfo;
	UWORD paramNo = 1;
	RETCODE retCode;
	int status = CRYPT_OK;

	assert( isWritePtr( dbmsInfo, DBMS_STATE_INFO ) );

	/* If we're aborting a transaction, roll it back, re-enable autocommit,
	   and clean up */
	if( updateType == DBMS_UPDATE_ABORT )
		{
		SQLTransact( dbmsInfo->hEnv, dbmsInfo->hDbc, SQL_ROLLBACK );
		SQLSetConnectOption( dbmsInfo->hDbc, SQL_AUTOCOMMIT, 1 );
		SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
		dbmsInfo->hStmt = NULL;
		return( CRYPT_OK );
		}

	/* If it's the start of a transaction, turn autocommit off */
	if( updateType == DBMS_UPDATE_BEGIN )
		SQLSetConnectOption( dbmsInfo->hDbc, SQL_AUTOCOMMIT, 0 );

	/* Allocate an hstmt unless we're in the middle of a transaction */
	if( updateType != DBMS_UPDATE_CONTINUE && \
		updateType != DBMS_UPDATE_COMMIT )
		SQLAllocStmt( dbmsInfo->hDbc, &dbmsInfo->hStmt );

	/* Bind in any necessary parameters to the hstmt.  This is unlike the
	   behaviour mentioned in the ODBC documentation, which claims that
	   SQLExecDirect() will return SQL_NEED_DATA if it finds a parameter
	   marker.  Instead, we have to bind the parameters before calling
	   SQLExecDirect() and it reads them from the bound location as required.
	   In addition an older version of the ODBC spec required that the
	   cbColDef value never exceed SQL_MAX_MESSAGE_LENGTH, however this is
	   defined to be 512 bytes, which means that we can't add most certs of 
	   any real complexity or with keys > 1K bits, so we pass in the actual 
	   data length here instead.  This works for all ODBC drivers tested */
	if( boundDate != 0 )
		{
		const struct tm *timeInfo = gmtime( &boundDate );

		/* Sanity check on input parameters */
		if( timeInfo == NULL )
			{
			SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
			dbmsInfo->hStmt = NULL;
			return( CRYPT_ERROR_BADDATA );
			}

		memset( &timestampInfo, 0, sizeof( TIMESTAMP_STRUCT ) );
		timestampInfo.year = timeInfo->tm_year + 1900;
		timestampInfo.month = timeInfo->tm_mon + 1;
		timestampInfo.day = timeInfo->tm_mday;
		timestampInfo.hour = timeInfo->tm_hour;
		timestampInfo.minute = timeInfo->tm_min;
		timestampInfo.second = timeInfo->tm_sec;
		SQLBindParameter( dbmsInfo->hStmt, paramNo++, SQL_PARAM_INPUT,
						  SQL_C_TIMESTAMP, SQL_TIMESTAMP, 0, 0,
						  &timestampInfo, 0, NULL );
		}
	if( boundData != NULL )
		{
		dbmsInfo->cbBlobLength = SQL_LEN_DATA_AT_EXEC( boundDataLength );
		SQLBindParameter( dbmsInfo->hStmt, paramNo++, SQL_PARAM_INPUT,
						  SQL_C_BINARY, dbmsInfo->blobType, boundDataLength, 0,
						  ( PTR ) 6, 0, &dbmsInfo->cbBlobLength );
		}

	/* Execute the command/hStmt as appropriate */
	if( command == NULL )
		retCode = SQLExecute( dbmsInfo->hStmt );
	else
		{
		char query[ MAX_SQL_QUERY_SIZE ];

		convertQuery( dbmsInfo, query, command );
		retCode = SQLExecDirect( dbmsInfo->hStmt, query, SQL_NTS );
		}
	if( retCode == SQL_NEED_DATA )
		{
		PTR pToken;

		/* Add the key data and perform a dummy SQLParamData() call to tell
		   the ODBC driver that we've finished with the operation */
		SQLParamData( dbmsInfo->hStmt, &pToken );
		retCode = SQLPutData( dbmsInfo->hStmt, ( PTR ) boundData,
							  boundDataLength );
		if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
			retCode = SQLParamData( dbmsInfo->hStmt, &pToken );
		}
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		/* If we hit an error at this point we can only exit if we're not
		   finishing a transaction.  If we are, the commit turns into an
		   abort further down */
		status = getErrorInfo( dbmsInfo, SQL_ERRLVL_2, CRYPT_ERROR_WRITE );
		if( updateType != DBMS_UPDATE_COMMIT )
			return( status );
		}
	else
		/* If we're performing a delete, the operation will succeed even
		   though nothing was found to delete so we make sure that we 
		   actually changed something */
		if( command != NULL && !strCompare( command, "DELETE", 6 ) )
			{
			SDWORD rowCount;

			SQLRowCount( dbmsInfo->hStmt, &rowCount );
			if( rowCount <= 0 )
				status = CRYPT_ERROR_NOTFOUND;
			}

	/* If it's the end of a transaction, commit the transaction and turn
	   autocommit on again */
	if( updateType == DBMS_UPDATE_COMMIT )
		{
		RETCODE retCode;

		/* If we've had a failure before this point, abort, otherwise
		   commit.  The UWORD cast is necessary in some development
		   environments (although spurious) */
		retCode = SQLTransact( dbmsInfo->hEnv, dbmsInfo->hDbc,
							   ( UWORD  ) ( cryptStatusError( status ) ? \
											SQL_ROLLBACK : SQL_COMMIT ) );
		SQLSetConnectOption( dbmsInfo->hDbc, SQL_AUTOCOMMIT, 1 );
		if( cryptStatusOK( status ) && \
			( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO ) )
			status = getErrorInfo( dbmsInfo, SQL_ERRLVL_2, CRYPT_ERROR_WRITE );
		}

	/* Clean up, unless we're in the middle of a transaction */
	if( updateType != DBMS_UPDATE_BEGIN && \
		updateType != DBMS_UPDATE_CONTINUE )
		{
		SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
		dbmsInfo->hStmt = NULL;
		}

	return( status );
	}

/* Perform a transaction that returns information */

static RETCODE fetchData( DBMS_STATE_INFO *dbmsInfo, char *data,
						  int *dataLength, const int maxLength,
						  const DBMS_QUERY_TYPE queryType )
	{
	const SWORD dataType = ( dbmsInfo->hasBinaryBlobs ) ? \
						   SQL_C_BINARY : SQL_C_CHAR;
	RETCODE retCode;
	SDWORD length;

	/* Get the results of the transaction */
	retCode = SQLFetch( dbmsInfo->hStmt );
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		return( retCode );

	/* If we're just doing a presence check, we don't bother fetching data */
	if( queryType == DBMS_QUERY_CHECK )
		return( SQL_SUCCESS );

	/* Read the data */
	retCode = SQLGetData( dbmsInfo->hStmt, 1, dataType, data, maxLength, 
						  &length );
	*dataLength = ( int ) length;

	return( retCode );
	}

static int performQuery( DBMS_STATE_INFO *dbmsInfo, const char *command,
						 char *data, int *dataLength, time_t boundDate,
						 const DBMS_QUERY_TYPE queryType )
	{
	/* We have to explicitly set the maximum length indicator because some
	   sources will helpfully zero-pad the data to the maximum indicated size,
	   which is smaller for the binary data */
	const int maxLength = dbmsInfo->hasBinaryBlobs ? \
						  MAX_CERT_SIZE : MAX_QUERY_RESULT_SIZE;
	const BOOLEAN isQuery = ( data == NULL ) ? TRUE : FALSE;
	char query[ MAX_SQL_QUERY_SIZE ];
	TIMESTAMP_STRUCT timestampInfo;
	RETCODE retCode;

	assert( isWritePtr( dbmsInfo, DBMS_STATE_INFO ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	/* Clear return value */
	*dataLength = 0;

	/* If we're cancelling a continuing query, clean up and exit */
	if( queryType == DBMS_QUERY_CANCEL )
		{
		/* Cancel any outstanding requests and free the statement handle.
		   The cancel isn't strictly necessary, but it means that the
		   SQLFreeStmt() doesn't return an error code to tell us that 
		   something was still happening */
		SQLCancel( dbmsInfo->hStmt );
		SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
		dbmsInfo->hStmt = NULL;
		return( CRYPT_OK );
		}

	/* If we're in the middle of a continuing query, fetch the next set of
	   results */
	if( queryType == DBMS_QUERY_CONTINUE )
		{
		retCode = fetchData( dbmsInfo, data, dataLength, maxLength,
							 DBMS_QUERY_CONTINUE );
		if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
			{
			int status;

			status = getErrorInfo( dbmsInfo, SQL_ERRLVL_2, CRYPT_ERROR_READ );
			SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
			dbmsInfo->hStmt = NULL;

			/* If we ran out of results we explicitly signal to the caller
			   that the query has completed */
			return( ( status == CRYPT_ERROR_NOTFOUND ) ? \
					CRYPT_ERROR_COMPLETE : CRYPT_ERROR_READ );
			}

		return( CRYPT_OK );
		}

	/* Allocate an hstmt and set the cursor concurrency to read-only */
	SQLAllocStmt( dbmsInfo->hDbc, &dbmsInfo->hStmt );
	if( queryType != DBMS_QUERY_START )
		/* Only return a maximum of a single row in response to a point
		   query.  This is a simple optimisation to ensure that the database
		   doesn't start sucking across huge amounts of data when it's not 
		   necessary */
		SQLSetConnectOption( dbmsInfo->hStmt, SQL_MAX_ROWS, 1 );
	SQLSetStmtOption( dbmsInfo->hStmt, SQL_CONCURRENCY,
					  SQL_CONCUR_READ_ONLY );

	/* Bind in any necessary parameters to the hstmt */
	if( boundDate != 0 )
		{
		struct tm *timeInfo = gmtime( &boundDate );

		/* Sanity check on input parameters */
		if( timeInfo == NULL )
			{
			SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
			dbmsInfo->hStmt = NULL;
			return( CRYPT_ERROR_BADDATA );
			}

		memset( &timestampInfo, 0, sizeof( TIMESTAMP_STRUCT ) );
		timestampInfo.year = timeInfo->tm_year + 1900;
		timestampInfo.month = timeInfo->tm_mon + 1;
		timestampInfo.day = timeInfo->tm_mday;
		timestampInfo.hour = timeInfo->tm_hour;
		timestampInfo.minute = timeInfo->tm_min;
		timestampInfo.second = timeInfo->tm_sec;
		SQLBindParameter( dbmsInfo->hStmt, 1, SQL_PARAM_INPUT,
						  SQL_C_TIMESTAMP, SQL_TIMESTAMP, 0, 0,
						  &timestampInfo, 0, NULL );
		}

	/* Execute the SQL statement */
	convertQuery( dbmsInfo, query, command );
	retCode = SQLExecDirect( dbmsInfo->hStmt, query, SQL_NTS );
	if( queryType != DBMS_QUERY_START && \
		( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO ) )
		retCode = fetchData( dbmsInfo, data, dataLength, maxLength,
							 queryType );

	/* Handle any errors */
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		int status;

		status = getErrorInfo( dbmsInfo, SQL_ERRLVL_2, CRYPT_ERROR_READ );
		SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
		dbmsInfo->hStmt = NULL;
		return( status );
		}
	if( queryType != DBMS_QUERY_START )
		{
		SQLFreeStmt( dbmsInfo->hStmt, SQL_DROP );
		dbmsInfo->hStmt = NULL;
		}

	return( CRYPT_OK );
	}

/* Fetch extended error information from the database state info */

static void performErrorQuery( DBMS_STATE_INFO *dbmsInfo, int *errorCode,
							   char *errorMessage )
	{
	assert( isWritePtr( dbmsInfo, DBMS_STATE_INFO ) );
	assert( isWritePtr( errorCode, sizeof( int ) ) );
	assert( isWritePtr( errorMessage, MAX_ERRMSG_SIZE ) );

	*errorCode = dbmsInfo->errorCode;
	strcpy( errorMessage, dbmsInfo->errorMessage );
	}

/* Pull in the shared database RPC routines, renaming the generic dispatch
   function to the ODBC-specific one which is called directly by the
   marshalling code */

#define processCommand( stateInfo, buffer ) \
		odbcProcessCommand( stateInfo, buffer )

#include "dbx_rpc.c"

#endif /* USE_ODBC */
