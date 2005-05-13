/****************************************************************************
*																			*
*						 cryptlib ODBC Mapping Routines						*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "dbms.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
  #include "dbms.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/dbms.h"
#endif /* Compiler-specific includes */

/* The following code can be run under any version of ODBC from 1.x to 3.x,
   although it assumes that a 3.x-level SDK is being used.  This is fairly
   likely, since this has been around since mid-1995.  If a pre-3.0 SDK is
   being used, then the following mappings will need to be applied:

	SQL_C_SLONG -> SQL_C_LONG
	SQLCHAR -> UCHAR
	SQLHANDLE -> Generic HENV/HSTMT/HDBC
	SQLHDBC -> HDBC
	SQLHENV -> HENV
	SQLHSTMT -> HSTMT
	SQLINTEGER -> SDWORD
	SQLPOINTER -> PTR
	SQLRETURN -> RETCODE
	SQLSMALLINT - SWORD
	SQLUINTEGER -> UDWORD
	SQLUSMALLINT -> UWORD

   Note that this can't be done automatically because the values are
   typedefs rather than #defines, which can't be detected at compile time.
   In addition under Windows the ODBC1x define needs to be used to enable
   the mapping of ODBC 1.x functions */

/* The ODBC 1.x SQLError() function returns error information at various
   levels and is rather unstable in its handling of input parameters, for
   example with some Win16 drivers if you pass it a valid hStmt then it may
   GPF after some calls so you need to force a NULL hStmt.  The following
   values define the levels of handle that we pass in in order for the ODBC
   1.x SQLError() to work as advertised.

   For ODBC 3.x only a single handle is used for SQLDiagRec(), but we still
   need these codes to indicate the type of the handle that's being passed */

#define SQL_ERRLVL_STMT	0
#define SQL_ERRLVL_DBC	1
#define SQL_ERRLVL_ENV	2

/* ODBC functions can return either SQL_SUCCESS or SQL_SUCCESS_WITH_INFO to
   indicate successful completion, to make them easier to work with we use
   a general status-check macro along the lines of cryptStatusOK() */

#define sqlStatusOK( status ) \
		( ( status ) == SQL_SUCCESS || ( status ) == SQL_SUCCESS_WITH_INFO )

#ifdef USE_ODBC

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

#ifdef DYNAMIC_LOAD

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL/shared libs's.  Explicitly linking to them will make cryptlib
   unloadable on some systems.

   MSDN updates from late 2000 defined SQLROWCOUNT themselves (which could be
   fixed by undefining it), however after late 2002 the value was typedef'd,
   requring all sorts of extra trickery to handle the different cases.
   Because of this this particular function is typedef'd with a _FN suffix
   to reduce problems */

static INSTANCE_HANDLE hODBC = NULL_INSTANCE;

typedef SQLRETURN ( SQL_API *SQLALLOCHANDLE )( SQLSMALLINT HandleType,
					SQLHANDLE InputHandle, SQLHANDLE *OutputHandlePtr );
typedef SQLRETURN ( SQL_API *SQLBINDPARAMETER )( SQLHSTMT StatementHandle,
					SQLUSMALLINT ParameterNumber, SQLSMALLINT InputOutputType,
					SQLSMALLINT ValueType, SQLSMALLINT ParameterType,
					SQLUINTEGER ColumnSize, SQLSMALLINT DecimalDigits,
					SQLPOINTER ParameterValuePtr, SQLINTEGER BufferLength,
					SQLINTEGER *StrLen_or_IndPtr );
typedef SQLRETURN ( SQL_API *SQLCLOSECURSOR )( SQLHSTMT StatementHandle );
typedef SQLRETURN ( SQL_API *SQLCONNECT )( SQLHDBC ConnectionHandle,
					SQLCHAR *ServerName, SQLSMALLINT NameLength1,
					SQLCHAR *UserName, SQLSMALLINT NameLength2,
					SQLCHAR *Authentication, SQLSMALLINT NameLength3 );
typedef SQLRETURN ( SQL_API *SQLDISCONNECT )( SQLHDBC ConnectionHandle );
typedef SQLRETURN ( SQL_API *SQLENDTRAN )( SQLSMALLINT HandleType,
					SQLHANDLE Handle, SQLSMALLINT CompletionType );
typedef SQLRETURN ( SQL_API *SQLEXECDIRECT )( SQLHSTMT StatementHandle,
					SQLCHAR *StatementText, SQLINTEGER TextLength );
typedef SQLRETURN ( SQL_API *SQLEXECUTE )( SQLHSTMT StatementHandle );
typedef SQLRETURN ( SQL_API *SQLFETCH )( SQLHSTMT StatementHandle );
typedef SQLRETURN ( SQL_API *SQLFREEHANDLE )( SQLSMALLINT HandleType,
					SQLHANDLE Handle );
typedef SQLRETURN ( SQL_API *SQLGETDATA )( SQLHSTMT StatementHandle,
					SQLUSMALLINT ColumnNumber, SQLSMALLINT TargetType,
					SQLPOINTER TargetValuePtr, SQLINTEGER BufferLength,
					SQLINTEGER *StrLen_or_IndPtr );
typedef SQLRETURN ( SQL_API *SQLGETDIAGREC )( SQLSMALLINT HandleType,
					SQLHANDLE Handle, SQLSMALLINT RecNumber,
					SQLCHAR *Sqlstate, SQLINTEGER *NativeErrorPtr,
					SQLCHAR *MessageText, SQLSMALLINT BufferLength,
					SQLSMALLINT *TextLengthPtr );
typedef SQLRETURN ( SQL_API *SQLGETINFO )( SQLHDBC ConnectionHandle,
					SQLUSMALLINT InfoType, SQLPOINTER InfoValuePtr,
					SQLSMALLINT BufferLength, SQLSMALLINT *StringLengthPtr );
typedef SQLRETURN ( SQL_API *SQLGETSTMTATTR )( SQLHSTMT StatementHandle,
					SQLINTEGER Attribute, SQLPOINTER ValuePtr,
					SQLINTEGER BufferLength, SQLINTEGER *StringLengthPtr );
typedef SQLRETURN ( SQL_API *SQLGETTYPEINFO )( SQLHSTMT StatementHandle,
					SQLSMALLINT DataType );
typedef SQLRETURN ( SQL_API *SQLPARAMDATA )( SQLHSTMT StatementHandle,
					SQLPOINTER *ValuePtrPtr );
typedef SQLRETURN ( SQL_API *SQLPREPARE )( SQLHSTMT StatementHandle,
					SQLCHAR *StatementText, SQLINTEGER TextLength );
typedef SQLRETURN ( SQL_API *SQLPUTDATA )( SQLHSTMT StatementHandle,
					SQLPOINTER DataPtr, SQLINTEGER StrLen_or_Ind );
typedef SQLRETURN ( SQL_API *SQLROWCOUNT_FN )( SQLHSTMT StatementHandle,
					SQLINTEGER *RowCountPtr );
typedef SQLRETURN ( SQL_API *SQLSETCONNECTATTR )( SQLHDBC ConnectionHandle,
					SQLINTEGER Attribute, SQLPOINTER ValuePtr,
					SQLINTEGER StringLength );
typedef SQLRETURN ( SQL_API *SQLSETENVATTR )( SQLHENV EnvironmentHandle,
					SQLINTEGER Attribute, SQLPOINTER ValuePtr,
					SQLINTEGER StringLength );
typedef SQLRETURN ( SQL_API *SQLSETSTMTATTR )( SQLHSTMT StatementHandle,
					SQLINTEGER Attribute, SQLPOINTER ValuePtr,
					SQLINTEGER StringLength );
#ifdef ODBC1x
typedef SQLRETURN ( SQL_API *SQLALLOCENV )( SQLHENV *phEnv );
typedef SQLRETURN ( SQL_API *SQLALLOCCONNECT )( SQLHENV hEnv,
					SQLHDBC *phDbc );
typedef SQLRETURN ( SQL_API *SQLALLOCSTMT )( SQLHDBC hDbc,
					SQLHSTMT *phStmt );
typedef SQLRETURN ( SQL_API *SQLERROR )( SQLHENV henv, SQLHDBC hDbc,
					SQLHSTMT hStmt, SQLCHAR *szSqlState,
					SQLINTEGER *pfNativeError, SQLCHAR *szErrorMsg,
					SQLSMALLINT cbErrorMsgMax, SQLSMALLINT *pcbErrorMsg );
typedef SQLRETURN ( SQL_API *SQLFREECONNECT )( SQLHDBC hDbc );
typedef SQLRETURN ( SQL_API *SQLFREEENV )( SQLHENV hEnv );
typedef SQLRETURN ( SQL_API *SQLFREESTMT )( SQLHSTMT hStmt, SQLUSMALLINT fOption );
typedef SQLRETURN ( SQL_API *SQLSETCONNECTOPTION )( SQLHDBC hdbc, UWORD fOption,
					UDWORD vParam );
typedef SQLRETURN ( SQL_API *SQLSETSTMTOPTION )( SQLHSTMT hstmt, UWORD fOption,
				  UDWORD vParam );
typedef SQLRETURN ( SQL_API *SQLTRANSACT )( SQLHENV hEnv, SQLHDBC hDbc, SQLUSMALLINT fType );
#endif /* ODBC1x */

static SQLALLOCHANDLE pSQLAllocHandle = NULL;
static SQLBINDPARAMETER pSQLBindParameter = NULL;
static SQLCLOSECURSOR pSQLCloseCursor = NULL;
static SQLCONNECT pSQLConnect = NULL;
static SQLDISCONNECT pSQLDisconnect = NULL;
static SQLENDTRAN pSQLEndTran = NULL;
static SQLEXECDIRECT pSQLExecDirect = NULL;
static SQLEXECUTE pSQLExecute = NULL;
static SQLFETCH pSQLFetch = NULL;
static SQLFREEHANDLE pSQLFreeHandle = NULL;
static SQLGETDATA pSQLGetData = NULL;
static SQLGETDIAGREC pSQLGetDiagRec = NULL;
static SQLGETINFO pSQLGetInfo = NULL;
static SQLGETSTMTATTR pSQLGetStmtAttr = NULL;
static SQLGETTYPEINFO pSQLGetTypeInfo = NULL;
static SQLPARAMDATA pSQLParamData = NULL;
static SQLPREPARE pSQLPrepare = NULL;
static SQLPUTDATA pSQLPutData = NULL;
static SQLROWCOUNT_FN pSQLRowCount = NULL;
static SQLSETCONNECTATTR pSQLSetConnectAttr = NULL;
static SQLSETENVATTR pSQLSetEnvAttr = NULL;
static SQLSETSTMTATTR pSQLSetStmtAttr = NULL;

#ifdef ODBC1x
static SQLALLOCCONNECT pSQLAllocConnect = NULL;
static SQLALLOCENV pSQLAllocEnv = NULL;
static SQLALLOCSTMT pSQLAllocStmt = NULL;
static SQLERROR pSQLError = NULL;
static SQLFREECONNECT pSQLFreeConnect = NULL;
static SQLFREEENV pSQLFreeEnv = NULL;
static SQLFREESTMT pSQLFreeStmt = NULL;
static SQLSETCONNECTOPTION pSQLSetConnectOption = NULL;
static SQLSETSTMTOPTION pSQLSetStmtOption = NULL;
static SQLTRANSACT pSQLTransact = NULL;
#endif /* ODBC1x */

/* The use of dynamically bound function pointers vs. statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define SQLAllocHandle			pSQLAllocHandle
#define SQLBindParameter		pSQLBindParameter
#define SQLCloseCursor			pSQLCloseCursor
#define SQLConnect				pSQLConnect
#define SQLDisconnect			pSQLDisconnect
#define SQLEndTran				pSQLEndTran
#define SQLExecDirect			pSQLExecDirect
#define SQLExecute				pSQLExecute
#define SQLFetch				pSQLFetch
#define SQLFreeHandle			pSQLFreeHandle
#define SQLGetData				pSQLGetData
#define SQLGetDiagRec			pSQLGetDiagRec
#define SQLGetInfo				pSQLGetInfo
#define SQLGetStmtAttr			pSQLGetStmtAttr
#define SQLGetTypeInfo			pSQLGetTypeInfo
#define SQLParamData			pSQLParamData
#define SQLPrepare				pSQLPrepare
#define SQLPutData				pSQLPutData
#define SQLRowCount				pSQLRowCount
#define SQLSetConnectAttr		pSQLSetConnectAttr
#define SQLSetEnvAttr			pSQLSetEnvAttr
#define SQLSetStmtAttr			pSQLSetStmtAttr

#ifdef ODBC1x
#define SQLAllocConnect			pSQLAllocConnect
#define SQLAllocEnv				pSQLAllocEnv
#define SQLAllocStmt			pSQLAllocStmt
#define SQLError				pSQLError
#define SQLFreeConnect			pSQLFreeConnect
#define SQLFreeEnv				pSQLFreeEnv
#define SQLFreeStmt				pSQLFreeStmt
#define SQLSetConnectOption		pSQLSetConnectOption
#define SQLSetStmtOption		pSQLSetStmtOption
#define SQLTransact				pSQLTransact
#endif /* ODBC1x */

/* Depending on whether we're running under Win16, Win32, or Unix we load the
   ODBC driver under a different name */

#if defined( __WIN16__ )
  #define ODBC_LIBNAME  "ODBC.DLL"
#elif defined( __WIN32__ )
  #define ODBC_LIBNAME  "ODBC32.DLL"
#elif defined( __UNIX__ )
  #if defined( __APPLE__ )
	/* OS X has built-in ODBC support via iODBC */
	#define ODBC_LIBNAME  "libiodbc.dylib"
  #else
	#define ODBC_LIBNAME  "libodbc.so"
  #endif /* Mac OS X vs. other Unixen */
#endif /* System-specific ODBC library names */

/* Dynamically load and unload any necessary DBMS libraries */

int dbxInitODBC( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */

	/* If the ODBC module is already linked in, don't do anything */
	if( hODBC != NULL_INSTANCE )
		return( CRYPT_OK );

	/* Obtain a handle to the module containing the ODBC functions */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hODBC = LoadLibrary( ODBC_LIBNAME );
	SetErrorMode( errorMode );
	if( hODBC < HINSTANCE_ERROR )
		{
		hODBC = NULL_INSTANCE;
		return( CRYPT_ERROR );
		}
#else
	if( ( hODBC = DynamicLoad( ODBC_LIBNAME ) ) == NULL_INSTANCE )
		return( CRYPT_ERROR );
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pSQLAllocHandle = ( SQLALLOCHANDLE ) DynamicBind( hODBC, "SQLAllocHandle" );
	pSQLBindParameter = ( SQLBINDPARAMETER ) DynamicBind( hODBC, "SQLBindParameter" );
	pSQLCloseCursor = ( SQLCLOSECURSOR ) DynamicBind( hODBC, "SQLCloseCursor" );
	pSQLConnect = ( SQLCONNECT ) DynamicBind( hODBC, "SQLConnect" );
	pSQLDisconnect = ( SQLDISCONNECT ) DynamicBind( hODBC, "SQLDisconnect" );
	pSQLEndTran = ( SQLENDTRAN ) DynamicBind( hODBC, "SQLEndTran" );
	pSQLExecDirect = ( SQLEXECDIRECT ) DynamicBind( hODBC, "SQLExecDirect" );
	pSQLExecute = ( SQLEXECUTE ) DynamicBind( hODBC, "SQLExecute" );
	pSQLFetch = ( SQLFETCH ) DynamicBind( hODBC, "SQLFetch" );
	pSQLFreeHandle = ( SQLFREEHANDLE ) DynamicBind( hODBC, "SQLFreeHandle" );
	pSQLGetData = ( SQLGETDATA ) DynamicBind( hODBC, "SQLGetData" );
	pSQLGetDiagRec = ( SQLGETDIAGREC ) DynamicBind( hODBC, "SQLGetDiagRec" );
	pSQLGetInfo = ( SQLGETINFO ) DynamicBind( hODBC, "SQLGetInfo" );
	pSQLGetStmtAttr = ( SQLGETSTMTATTR ) DynamicBind( hODBC, "SQLGetStmtAttr" );
	pSQLGetTypeInfo = ( SQLGETTYPEINFO ) DynamicBind( hODBC, "SQLGetTypeInfo" );
	pSQLParamData = ( SQLPARAMDATA ) DynamicBind( hODBC, "SQLParamData" );
	pSQLPrepare = ( SQLPREPARE ) DynamicBind( hODBC, "SQLPrepare" );
	pSQLPutData = ( SQLPUTDATA ) DynamicBind( hODBC, "SQLPutData" );
	pSQLRowCount = ( SQLROWCOUNT_FN ) DynamicBind( hODBC, "SQLRowCount" );
	pSQLSetConnectAttr = ( SQLSETCONNECTATTR ) DynamicBind( hODBC, "SQLSetConnectAttr" );
	pSQLSetEnvAttr = ( SQLSETENVATTR ) DynamicBind( hODBC, "SQLSetEnvAttr" );
	pSQLSetStmtAttr = ( SQLSETSTMTATTR ) DynamicBind( hODBC, "SQLSetStmtAttr" );

#ifdef ODBC1x
	pSQLAllocConnect = ( SQLALLOCCONNECT ) DynamicBind( hODBC, "SQLAllocConnect" );
	pSQLAllocEnv = ( SQLALLOCENV ) DynamicBind( hODBC, "SQLAllocEnv" );
	pSQLAllocStmt = ( SQLALLOCSTMT ) DynamicBind( hODBC, "SQLAllocStmt" );
	pSQLError = ( SQLERROR ) DynamicBind( hODBC, "SQLError" );
	pSQLFreeConnect = ( SQLFREECONNECT ) DynamicBind( hODBC, "SQLFreeConnect" );
	pSQLFreeEnv = ( SQLFREEENV ) DynamicBind( hODBC, "SQLFreeEnv" );
	pSQLFreeStmt = ( SQLFREESTMT ) DynamicBind( hODBC, "SQLFreeStmt" );
	pSQLSetConnectOption = ( SQLSETCONNECTOPTION ) DynamicBind( hODBC, "SQLSetConnectOption" );
	pSQLSetStmtOption = ( SQLSETSTMTOPTION ) DynamicBind( hODBC, "SQLSetStmtOption" );
	pSQLTransact = ( SQLTRANSACT ) DynamicBind( hODBC, "SQLTransact" );
#endif /* ODBC1x */

	/* Make sure that we got valid pointers for every ODBC function */
	if( pSQLAllocHandle == NULL || pSQLBindParameter == NULL ||
		pSQLCloseCursor == NULL || pSQLConnect == NULL ||
		pSQLDisconnect == NULL || pSQLEndTran == NULL ||
		pSQLExecDirect == NULL || pSQLExecute == NULL ||
		pSQLFetch == NULL || pSQLFreeHandle == NULL ||
		pSQLGetData == NULL || pSQLGetDiagRec == NULL ||
		pSQLGetInfo == NULL || pSQLGetStmtAttr == NULL ||
		pSQLGetTypeInfo == NULL || pSQLParamData == NULL ||
		pSQLPrepare == NULL || pSQLPutData == NULL ||
		pSQLSetConnectAttr == NULL || pSQLSetEnvAttr == NULL ||
		pSQLSetStmtAttr == NULL )
		{
		/* Free the library reference and reset the handle */
		DynamicUnload( hODBC );
		hODBC = NULL_INSTANCE;
		return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

void dbxEndODBC( void )
	{
	if( hODBC != NULL_INSTANCE )
		DynamicUnload( hODBC );
	hODBC = NULL_INSTANCE;
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

/* Get information on an ODBC error.  The statement handle is specified as a
   distinct parameter because it may be an ephemeral handle not part of the
   state info data */

static int getErrorInfo( DBMS_STATE_INFO *dbmsInfo, const int errorLevel,
						 SQLHSTMT hStmt, const int defaultStatus )
	{
#ifdef ODBC1x
	SQLHDBC hdbc = ( errorLevel < 1 ) ? SQL_NULL_HDBC : dbmsInfo->hDbc;
	SQLHSTMT hstmt = ( errorLevel < 2 ) ? SQL_NULL_HSTMT : dbmsInfo->hStmt;
#else
	const SQLSMALLINT handleType = ( errorLevel == SQL_ERRLVL_STMT ) ? \
										SQL_HANDLE_STMT : \
								   ( errorLevel == SQL_ERRLVL_DBC ) ? \
										SQL_HANDLE_DBC : SQL_HANDLE_ENV;
	const SQLHANDLE handle = ( errorLevel == SQL_ERRLVL_STMT ) ? \
								hStmt : \
							 ( errorLevel == SQL_ERRLVL_DBC ) ? \
								dbmsInfo->hDbc : dbmsInfo->hEnv;
#endif /* ODBC1x */
	char szSqlState[ SQL_SQLSTATE_SIZE ];
	SQLUINTEGER dwNativeError = 0;
	SQLSMALLINT dummy;
	SQLRETURN sqlStatus;

#ifdef ODBC1x
	/* Get the initial ODBC error info.  Some of the information returned by
	   SQLError() is pretty odd.  It usually returns an ANSI SQL2 error
	   state in SQLSTATE, but also returns a native error code in NativeError.
	   However the NativeError codes aren't documented anywhere, so we rely
	   on SQLSTATE having a useful value.  We pre-set the native error codes
	   to zero because they sometimes aren't set by SQLError() */
	sqlStatus = SQLError( dbmsInfo->hEnv, hdbc, hstmt, szSqlState,
						  &dwNativeError, dbmsInfo->errorMessage,
						  MAX_ERRMSG_SIZE - 1, &dummy );
	dbmsInfo->errorCode = ( int ) dwNativeError;	/* Usually 0 */
	if( !strncmp( szSqlState, "01004", 5 ) )
		{
		/* Work around a bug in ODBC 2.0 drivers (still present on older
		   NT 4 machines) in which the primary error is some bizarre
		   nonsense value (string data right truncated, even though there's
		   no output data to truncate) and the actual error is present at
		   the second level, obtained by calling SQLError() a second time */
		dwNativeError = 0;
		sqlStatus = SQLError( dbmsInfo->hEnv, hdbc, hstmt, szSqlState,
							  &dwNativeError, dbmsInfo->errorMessage,
							  MAX_ERRMSG_SIZE - 1, &dummy );
		}
#else
	/* Get the ODBC error info at the most detailed level we can manage */
	sqlStatus = SQLGetDiagRec( handleType, handle, 1, szSqlState,
							   &dwNativeError, dbmsInfo->errorMessage,
							   MAX_ERRMSG_SIZE - 1, &dummy );
	if( !sqlStatusOK( sqlStatus ) && errorLevel == SQL_ERRLVL_STMT )
		/* If we couldn't get info at the statement-handle level, try again
		   at the connection handle level */
		sqlStatus = SQLGetDiagRec( SQL_HANDLE_DBC, dbmsInfo->hDbc, 1,
								   szSqlState, &dwNativeError,
								   dbmsInfo->errorMessage,
								   MAX_ERRMSG_SIZE - 1, &dummy );
	if( !sqlStatusOK( sqlStatus ) )
		{
		assert( NOTREACHED );	/* Catch this if it ever occurs */
		strcpy( dbmsInfo->errorMessage, "Couldn't get error information "
				"from database backend" );
		return( CRYPT_ERROR_FAILED );
		}
#endif /* ODBC1x */

	/* Check for a not-found error status.  We can also get an sqlStatus of
	   SQL_NO_DATA with SQLSTATE set to "00000" and the error message string
	   empty in some cases, in which case we provide our own error string */
	if( !strncmp( szSqlState, "S0002", 5 ) ||	/* ODBC 2.x */
		!strncmp( szSqlState, "42S02", 5 ) ||	/* ODBC 3.x */
		( !strncmp( szSqlState, "00000", 5 ) && \
		  sqlStatus == SQL_NO_DATA ) )
		{
		/* Make sure that the caller gets a sensible error message if they
		   try to examine the extended error information */
		if( !*dbmsInfo->errorMessage )
			strcpy( dbmsInfo->errorMessage, "No data found" );
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

/* Rewrite the SQL query to handle the back-end specific blob and date type,
   and work around problems with some back-end types (and we're specifically
   talking Access here) */

static void convertQuery( DBMS_STATE_INFO *dbmsInfo, char *query,
						  const char *command )
	{
	SQLRETURN sqlStatus;
	SQLSMALLINT bufLen;
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

	/* If it's not a SELECT/DELETE with wildcards used, there's nothing to
	   do */
	if( ( strncmp( query, "SELECT", 6 ) && strncmp( query, "DELETE", 6 ) ) || \
		  strstr( query, " LIKE " ) == NULL )
		return;

	/* It's a potential problem command, check for the presence of Access */
	sqlStatus = SQLGetInfo( dbmsInfo->hDbc, SQL_DBMS_NAME, buffer,
							sizeof( buffer ), &bufLen );
	if( sqlStatusOK( sqlStatus ) && \
		strCompare( buffer, "Access", 6 ) )
		return;

	/* Unlike everything else in the known universe, Access uses * and ?
	   instead of the standard SQL wildcards so if we find a LIKE ... %
	   we rewrite the % as a * */
	if( ( keywordPtr = strstr( query, " LIKE " ) ) != NULL )
		{
		int i;

		/* Search up to 6 characters ahead for a wildcard and replace it
		   with the one needed by Access if we find it.  We search 6 chars
		   ahead because the higher-level SQL code uses expressions like
		   "SELECT .... WHERE foo LIKE '--%'", which is 5 chars plus one as
		   a safety margin */
		for( i = 7; i < 11 && keywordPtr[ i ]; i++ )
			if( keywordPtr[ i ] == '%' )
				keywordPtr[ i ] = '*';
		}
	}

/* Get data type info for this data source.  Since SQLGetTypeInfo() returns
   a variable (and arbitrary) length result set, we have to call
   SQLCloseCursor() after each fetch before performing a new query */

static int getBlobInfo( DBMS_STATE_INFO *dbmsInfo, const SQLSMALLINT type )
	{
	const SQLHSTMT hStmt = dbmsInfo->hStmt[ 0 ];
	SQLRETURN sqlStatus;
	SQLUINTEGER length;
	SQLINTEGER count;

	/* Check for support for the requested blob type and get the results of
	   the transaction.  If the database doesn't support this, we'll get an
	   SQL_NO_DATA status */
	sqlStatus = SQLGetTypeInfo( hStmt, type );
	if( sqlStatusOK( sqlStatus ) )
		sqlStatus = SQLFetch( hStmt );
	if( !sqlStatusOK( sqlStatus ) )
		return( CRYPT_ERROR );

	/* Get the type name (result column 1) and column size (= maximum
	   possible field length, result column 3).  We only check the second
	   return code since they both apply to the same row */
	SQLGetData( hStmt, 1, SQL_C_CHAR, dbmsInfo->blobName,
				CRYPT_MAX_TEXTSIZE, &length );
	sqlStatus = SQLGetData( hStmt, 3, SQL_C_SLONG, &count,
							sizeof( SQLINTEGER ), &length );
	SQLCloseCursor( hStmt );
	if( !sqlStatusOK( sqlStatus ) )
		return( CRYPT_ERROR );

	/* We've got the blob type, remember the details */
	if( type == SQL_LONGVARBINARY )
		dbmsInfo->hasBinaryBlobs = TRUE;
	dbmsInfo->blobType = type;
	return( count );
	}

static int getDatatypeInfo( DBMS_STATE_INFO *dbmsInfo, int *featureFlags )
	{
	const SQLHSTMT hStmt = dbmsInfo->hStmt[ 0 ];
	SQLRETURN sqlStatus;
	SQLSMALLINT bufLen;
	SQLUSMALLINT transactBehaviour;
	SQLINTEGER attrLength;
	SQLUINTEGER privileges;
	char buffer[ 8 ];
	int count;

	/* First we see what the back-end's blob data type is.  Usually it'll
	   be binary blobs, if that doesn't work we try for char blobs */
	count = getBlobInfo( dbmsInfo, SQL_LONGVARBINARY );
	if( cryptStatusError( count ) )
		count = getBlobInfo( dbmsInfo, SQL_LONGVARCHAR );
	if( cryptStatusError( count ) )
		return( getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
							  CRYPT_ERROR_OPEN ) );
	if( dbmsInfo->hasBinaryBlobs )
		*featureFlags |= DBMS_HAS_BINARYBLOBS;

	/* If we couldn't get a blob type or the type is too short to use,
	   report it back as a database open failure */
	if( count < MAX_ENCODED_CERT_SIZE )
		{
		sprintf( dbmsInfo->errorMessage, "Database blob type can only "
				 "store %d bytes, we need at least %d", count,
				 MAX_ENCODED_CERT_SIZE );
		return( CRYPT_ERROR_OPEN );
		}

	/* Sanity check, make sure that the source can return the required
	   amount of data.  A number of data sources don't support this
	   attribute (it's mostly meant to be set by applications rather than
	   being read, and is intended to be used to reduce network traffic)
	   so we don't worry if it's not available.  In addition to the maximum-
	   size check we also have to perform a minimum-size check, since a
	   value of zero is used to indicate no length limit */
	sqlStatus = SQLGetStmtAttr( hStmt, SQL_ATTR_MAX_LENGTH,
								( SQLPOINTER ) &attrLength, SQL_IS_INTEGER,
								NULL );
	if( sqlStatusOK( sqlStatus ) && \
		attrLength > 0 && attrLength < MAX_SQL_QUERY_SIZE )
		{
		sprintf( dbmsInfo->errorMessage, "Database back-end can only "
				 "transmit %d bytes per message, we need at least %d",
				 attrLength, MAX_SQL_QUERY_SIZE );
		return( CRYPT_ERROR_OPEN );
		}

	/* Now do the same thing for the date+time data type.  This changed from
	   SQL_TIMESTAMP in ODBC 2.x to SQL_TYPE_TIMESTAMP in ODBC 3.x, since 3.x
	   will be more common we try the 3.x version first and if that fails
	   fall back to 2.x */
	sqlStatus = SQLGetTypeInfo( hStmt, SQL_TYPE_TIMESTAMP );
	if( !sqlStatusOK( sqlStatus ) )
		sqlStatus = SQLGetTypeInfo( hStmt, SQL_TIMESTAMP );
	if( sqlStatusOK( sqlStatus ) )
		{
		SQLUINTEGER length;

		/* Fetch the results of the transaction and get the type name (result
		   column 1) and column size (result column 3).  The column size
		   argument is quite problematic because although some back-ends
		   have a fixed size for this (and usually ignore the column-size
		   parameter), others allow multiple time representations and
		   require an explicit column-size indicator to decide which one
		   they should use.  The ODBC standard representation for example
		   uses 19 chars (yyyy-mm-dd hh:mm:ss) for the full date+time that
		   we use here, but also allows a 16-char version without the seconds
		   and a 20+n-char version for n digits of fractional seconds.  The
		   back-end however may use a completely different value, for
		   example Oracle encodes the full date+time as 7 bytes (century,
		   year, month, day, hour, minute, second).  To get around this we
		   get the first column-size value (which is usually the only one
		   available), if this is the same as the ODBC standard minimum-size
		   column we try for more results to see if the full date+time form
		   is available, and use that if it is */
		sqlStatus = SQLFetch( hStmt );
		if( sqlStatusOK( sqlStatus ) )
			sqlStatus = SQLGetData( hStmt, 1, SQL_C_CHAR,
									dbmsInfo->dateTimeName,
									CRYPT_MAX_TEXTSIZE, &length );
		if( sqlStatusOK( sqlStatus ) )
			sqlStatus = SQLGetData( hStmt, 3, SQL_C_SLONG,
									&dbmsInfo->dateTimeNameColSize,
									sizeof( SQLINTEGER ), &length );
		if( sqlStatusOK( sqlStatus ) && \
			dbmsInfo->dateTimeNameColSize == 16 )
			{
			SQLINTEGER columnSize;

			/* Some back-ends allow multiple formats for the date+time
			   column, if the back-end reports the short (no-seconds) ODBC-
			   default format see whether it'll support the longer (with
			   seconds) format instead */
			sqlStatus = SQLFetch( hStmt );
			if( sqlStatusOK( sqlStatus ) )
				sqlStatus = SQLGetData( hStmt, 3, SQL_C_SLONG,
										&columnSize, sizeof( SQLINTEGER ),
										&length );
			if( sqlStatusOK( sqlStatus ) && columnSize == 19 )
				dbmsInfo->dateTimeNameColSize = columnSize;
			}
		SQLCloseCursor( hStmt );
		}
	if( !sqlStatusOK( sqlStatus ) )
		return( getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
							  CRYPT_ERROR_OPEN ) );

#if 0	/* Not needed, we always supply the length at bind time */
	/* Determine whether we can supply the length of blob data at
	   parameter bind time (result = 'Y') or we have to defer it to
	   statement execution time (result = 'N') */
	sqlStatus = SQLGetInfo( dbmsInfo->hDbc, SQL_NEED_LONG_DATA_LEN,
							buffer, sizeof( buffer ), &bufLen );
	if( sqlStatusOK( sqlStatus ) )
		dbmsInfo->needLongLength = ( *buffer == 'Y' ) ? TRUE : FALSE;
	else
		dbmsInfo->needLongLength = TRUE;	/* Make a paranoid guess */
#endif /* 0 */

	/* Determine whether we can write to the database (result = 'Y') or not
	   (result = 'N') */
	sqlStatus = SQLGetInfo( dbmsInfo->hDbc, SQL_DATA_SOURCE_READ_ONLY,
							buffer, sizeof( buffer ), &bufLen );
	if( sqlStatusOK( sqlStatus ) && *buffer == 'Y' )
		*featureFlags |= DBMS_HAS_NOWRITE;

	/* Determine whether GRANT/REVOKE capabilities are available.  This gets
	   a bit messy because it only specifies which extended GRANT/REVOKE
	   options are available, rather than whether GRANT/REVOKE is available
	   at all.  To handle this, we treat GRANT/REVOKE as being available if
	   any information is returned (SQL Server typically returns only
	   SQL_SG_WITH_GRANT_OPTION while other sources like DB2, Postgres, and
	   Sybase return the correct set of flags) and not available if nothing
	   is returned (Access, dBASE, Paradox, etc).  To make things especially
	   challenging, Informix returns nothing for SQL_SQL92_GRANT but does
	   return something for SQL_SQL92_REVOKE, so we have to check both and
	   allow GRANT/REVOKE if either test positive */
	sqlStatus = SQLGetInfo( dbmsInfo->hDbc, SQL_SQL92_GRANT,
							( SQLPOINTER ) &privileges,
							sizeof( SQLUINTEGER ), &bufLen );
	if( sqlStatusOK( sqlStatus ) && privileges )
		*featureFlags |= DBMS_HAS_PRIVILEGES;
	sqlStatus = SQLGetInfo( dbmsInfo->hDbc, SQL_SQL92_REVOKE,
							( SQLPOINTER ) &privileges,
							sizeof( SQLUINTEGER ), &bufLen );
	if( sqlStatusOK( sqlStatus ) && privileges )
		*featureFlags |= DBMS_HAS_PRIVILEGES;

	/* Check how the back-end reacts to commit/rollback commands.  If
	   transactions are destructive (that is, prepared statements are
	   cleared when a commit/rollback is performed), we have to clear the
	   hStmtPrepared[] array to indicate that all statements have to be
	   re-prepared.  Fortunately this is quite rare, both because most
	   back-ends don't do this (for virtually all ODBC-accessible data
	   sources (SQL Server, Access, dBASE, Paradox, etc etc) the behaviour
	   is SQL_CB_CLOSE, meaning that the currently active cursor is closed
	   but there's no need to call SQLPrepare() again) and because it only
	   affects CA cert stores opened in read/write mode */
	sqlStatus = SQLGetInfo( dbmsInfo->hDbc, SQL_CURSOR_COMMIT_BEHAVIOR,
							&transactBehaviour, sizeof( SQLUSMALLINT ),
							&bufLen );
	if( sqlStatusOK( sqlStatus ) && transactBehaviour == SQL_CB_DELETE )
		dbmsInfo->transactIsDestructive = TRUE;
	sqlStatus = SQLGetInfo( dbmsInfo->hDbc, SQL_CURSOR_ROLLBACK_BEHAVIOR,
							&transactBehaviour, sizeof( SQLUSMALLINT ),
							&bufLen );
	if( sqlStatusOK( sqlStatus ) && transactBehaviour == SQL_CB_DELETE )
		dbmsInfo->transactIsDestructive = TRUE;

	/* Finally, determine the escape char being used.  This is usually '\',
	   but it may have been changed for some reason */
	sqlStatus = SQLGetInfo( dbmsInfo->hDbc, SQL_SEARCH_PATTERN_ESCAPE,
							buffer, sizeof( buffer ), &bufLen );
	dbmsInfo->escapeChar = sqlStatusOK( sqlStatus ) ? buffer[ 0 ] : '\\';

	return( CRYPT_OK );
	}

/* Bind parameters for a query/update.  The caller has to supply the bound
   data storage since it still has to exist later on when the query is
   executed */

static int bindParameters( const SQLHSTMT hStmt, const char *boundData,
						   const int boundDataLength, const time_t boundDate,
						   TIMESTAMP_STRUCT *timestampStorage,
						   SQLINTEGER *lengthStorage,
						   DBMS_STATE_INFO *dbmsInfo,
						   const BOOLEAN bindForQuery )
	{
	SQLUSMALLINT paramNo = 1;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_STATE_INFO ) ) );

	/* Bind in any necessary parameters to the hStmt.  If there's a bound
	   date parameter present it'll always come before the bound data, so
	   we bind the date first */
	if( boundDate > 0 )
		{
		SQLRETURN sqlStatus;
		const struct tm *timeInfo = gmtime( &boundDate );

		assert( isWritePtr( timestampStorage, sizeof( TIMESTAMP_STRUCT ) ) );

		/* Sanity check on input parameters */
		if( timestampStorage == NULL )
			return( CRYPT_ERROR_BADDATA );

		/* Bind in the date.  The handling of the ColumnSize parameter is
		   ugly, this value should be implicit in the underlying data type,
		   but a small number of back-ends (e.g. ones derived from the
		   Sybase 4.2 code line, which includes the current Sybase and SQL
		   Server) may support multiple time representations and require an
		   explicit length indicator to decide which one they should use
		   (not helped by the fact that the sample code in the
		   SQLBindParameter() manpage gives the ColumnSize parameter for
		   date/time types as zero, implying that it's ignored by the
		   driver).

		   Unfortunately the fact that some drivers specifically require
		   this parameter means that we have to provide an explicit length
		   value, see the comment in getDatatypeInfo() for how this is
		   obtained.  Luckily the majority of back-ends have a single pre-
		   set value for this and ignore the length value, so the chances of
		   running into something that both requires the parameter and fails
		   the guesstimation procedure used in getDatatypeInfo() is small */
		memset( timestampStorage, 0, sizeof( TIMESTAMP_STRUCT ) );
		timestampStorage->year = timeInfo->tm_year + 1900;
		timestampStorage->month = timeInfo->tm_mon + 1;
		timestampStorage->day = timeInfo->tm_mday;
		timestampStorage->hour = timeInfo->tm_hour;
		timestampStorage->minute = timeInfo->tm_min;
		timestampStorage->second = timeInfo->tm_sec;
		sqlStatus = SQLBindParameter( hStmt, paramNo++, SQL_PARAM_INPUT,
									  SQL_C_TIMESTAMP, SQL_TIMESTAMP,
									  dbmsInfo->dateTimeNameColSize, 0,
									  timestampStorage, 0, NULL );
		if( !sqlStatusOK( sqlStatus ) )
			return( getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
								  CRYPT_ERROR_BADDATA ) );
		}
	if( boundData != NULL )
		{
		SQLSMALLINT valueType, parameterType;
		SQLRETURN sqlStatus;

		assert( boundDataLength > 0 && \
				isReadPtr( boundData, boundDataLength ) );
		assert( isWritePtr( lengthStorage, sizeof( SQLINTEGER ) ) );

		/* Bind the query data in one of two ways depending on whether we're
		   binding for a query or an update.  The effective difference
		   between the two is mostly ODBC voodoo related to how lengths are
		   specified, if it isn't done this way then Access (the default
		   ODBC data source on most Windows systems) returns "String data,
		   right truncated (null)" errors at random.  No-one knows what the
		   cause is, and the only known fix is to juggle parameters until it
		   stops happening, although in some cases it appears to be because
		   it ignores the length value for SQL_CHAR data and tries to find a
		   terminating null character past the end of the string */
		if( bindForQuery )
			valueType = parameterType = SQL_C_CHAR;
		else
			{
			valueType = ( dbmsInfo->hasBinaryBlobs ) ? SQL_C_BINARY : \
													   SQL_C_CHAR;
			parameterType = dbmsInfo->blobType;
			}
		*lengthStorage = boundDataLength;
		sqlStatus = SQLBindParameter( hStmt, paramNo++, SQL_PARAM_INPUT,
									  valueType, parameterType,
									  boundDataLength, 0,
									  ( SQLPOINTER ) boundData,
									  boundDataLength, lengthStorage );
		if( !sqlStatusOK( sqlStatus ) )
			return( getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
								  CRYPT_ERROR_BADDATA ) );
		}

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
	int i;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_STATE_INFO ) ) );

	/* Commit the transaction.  The default transaction mode is auto-commit
	   so the SQLEndTran() call isn't strictly necessary, but we play it
	   safe anyway */
	if( dbmsInfo->needsUpdate )
		{
		SQLEndTran( SQL_HANDLE_DBC, dbmsInfo->hDbc, SQL_COMMIT );
		dbmsInfo->needsUpdate = FALSE;
		}

	/* Clean up */
	for( i = 0; i < NO_CACHED_QUERIES; i++ )
		if( dbmsInfo->hStmt[ i ] != NULL )
			{
			SQLFreeHandle( SQL_HANDLE_STMT, dbmsInfo->hStmt[ i ] );
			dbmsInfo->hStmtPrepared[ i ] = FALSE;
			dbmsInfo->hStmt[ i ] = NULL;
			}
	SQLDisconnect( dbmsInfo->hDbc );
	SQLFreeHandle( SQL_HANDLE_DBC, dbmsInfo->hDbc );
	SQLFreeHandle( SQL_HANDLE_ENV, dbmsInfo->hEnv );
	dbmsInfo->hDbc = NULL;
	dbmsInfo->hEnv = NULL;
	}

/* Open a connection to a data source.  We don't check the return codes for
   many of the parameter-fiddling functions since the worst that can happen
   if they fail is that performance will be somewhat suboptimal.

   For the somewhat flaky Win16 ODBC 1.x/2.x, it wasn't safe to allocate
   statement handles at this point since these were handled in various
   strange and peculiar ways by different ODBC drivers.  The main problem was
   that some drivers didn't support more than one hStmt per hDbc, some
   supported only one active hStmt (an hStmt with results pending) per hDbc,
   and some supported multiple active hStmt's per hDbc.  For this reason the
   older ODBC glue code used a strategy of allocating an hStmt, performing a
   transaction, and then immediately freeing it again afterwards.

   For any newer ODBC driver this isn't a problem any more (particularly when
   it's necessary to accomodate threads), so we can allocate the hStmt here.
   In addition to the main hStmt we also allocate a number of additional
   hStmts used to contain pre-prepared, cached instances of frequently-
   executed queries.  This means that the expensive step of parsing the SQL
   query, validating it against the system catalog, preparing an access
   plan, and optimising the plan, are only performed once on the first query
   rather than at every single access.  If it's necessary to work with a
   buggy ODBC driver that can't support multiple hStmts then everything can
   be directed through the primary hStmt, at some loss in performance */

static int openDatabase( DBMS_STATE_INFO *dbmsInfo, const char *name,
						 const int options, int *featureFlags )
	{
	DBMS_NAME_INFO nameInfo;
	SQLRETURN sqlStatus;
	int i, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_STATE_INFO ) ) );
	assert( isReadPtr( name, 2 ) );
	assert( isWritePtr( featureFlags, sizeof( int ) ) );

	/* Clear return values */
	memset( dbmsInfo, 0, sizeof( DBMS_STATE_INFO ) );
	*featureFlags = DBMS_HAS_NONE;

#ifdef DYNAMIC_LOAD
	/* Make sure that the driver is bound in */
	if( hODBC == NULL_INSTANCE )
		return( CRYPT_ERROR_OPEN );
#endif /* DYNAMIC_LOAD */

	/* Parse the data source into its individual components */
	status = dbmsParseName( &nameInfo, name, SQL_NTS );
	if( cryptStatusError( status ) )
		return( status );

	/* Allocate environment and connection handles.  Before we do anything
	   with the environment handle we have to set the ODBC version to 3 or
	   any succeeding calls will fail with a function sequence error.  God
	   knows why they couldn't assume a default setting of ODBC 3.x for this
	   value when it requires an ODBC 3.x function call to get here in the
	   first place */
	sqlStatus = SQLAllocHandle( SQL_HANDLE_ENV, SQL_NULL_HANDLE,
								&dbmsInfo->hEnv );
	if( !sqlStatusOK( sqlStatus ) )
		{
		/* We can't get any error details without at least an environment
		   handle, so all we can do is return a generic allocation error
		   message.  If we get a failure at this point (and in particular
		   on the very first ODBC call) it's usually a sign of an incorrect
		   ODBC install or config (on non-Windows systems where it's not
		   part of the OS), since the ODBC driver can't initialise itself */
#ifdef __WINDOWS__
		strcpy( dbmsInfo->errorMessage, "Couldn't allocate database "
				"connection handle" );
#else
		strcpy( dbmsInfo->errorMessage, "Couldn't allocate database "
				"connection handle, this is probably due to an incorrect "
				"ODBC driver install or an invalid configuration" );
#endif /* __WINDOWS__ */
		return( CRYPT_ERROR_OPEN );
		}
	SQLSetEnvAttr( dbmsInfo->hEnv, SQL_ATTR_ODBC_VERSION,
				   ( SQLPOINTER ) SQL_OV_ODBC3, SQL_IS_INTEGER );
	sqlStatus = SQLAllocHandle( SQL_HANDLE_DBC, dbmsInfo->hEnv,
								&dbmsInfo->hDbc );
	if( !sqlStatusOK( sqlStatus ) )
		{
		status = getErrorInfo( dbmsInfo, SQL_ERRLVL_ENV, SQL_NULL_HSTMT,
							   CRYPT_ERROR_OPEN );
		SQLFreeHandle( SQL_HANDLE_ENV, dbmsInfo->hEnv );
		return( status );
		}

	/* Once everything is set up the way we want it, try to connect to a data
	   source and allocate a statement handle */
	sqlStatus = SQLConnect( dbmsInfo->hDbc,
							nameInfo.name, ( SQLSMALLINT ) nameInfo.nameLen,
							nameInfo.user, ( SQLSMALLINT ) nameInfo.userLen,
							nameInfo.password, ( SQLSMALLINT ) nameInfo.passwordLen );
	if( !sqlStatusOK( sqlStatus ) )
		{
		status = getErrorInfo( dbmsInfo, SQL_ERRLVL_DBC, SQL_NULL_HSTMT,
							   CRYPT_ERROR_OPEN );
		closeDatabase( dbmsInfo );
		return( status );
		}

	/* Now that the connection is open, allocate the statement handles */
	for( i = 0; i < NO_CACHED_QUERIES && sqlStatusOK( sqlStatus ); i++ )
		sqlStatus = SQLAllocHandle( SQL_HANDLE_STMT, dbmsInfo->hDbc,
									&dbmsInfo->hStmt[ i ] );
	if( !sqlStatusOK( sqlStatus ) )
		{
		status = getErrorInfo( dbmsInfo, SQL_ERRLVL_DBC, SQL_NULL_HSTMT,
							   CRYPT_ERROR_OPEN );
		closeDatabase( dbmsInfo );
		return( status );
		}

	/* Set the access mode to read-only if we can.  The default is R/W, but
	   setting it to read-only optimises transaction management */
	if( options == CRYPT_KEYOPT_READONLY )
		SQLSetStmtAttr( dbmsInfo->hDbc, SQL_ATTR_ACCESS_MODE,
						( SQLPOINTER ) SQL_MODE_READ_ONLY, SQL_IS_INTEGER );

	/* Set the cursor type to forward-only (which should be the default
	   anyway), concurrency to read-only if we're opening the database in
	   read-only mode (this again should be the default), and turn off
	   scanning for escape clauses in the SQL strings, which lets the driver
	   pass the string directly to the data source.  The latter improves
	   both performance and (to some extent) security by reducing the
	   chances of hostile SQL injection, or at least by requiring specially
	   crafted back-end specific SQL rather than generic ODBC SQL to
	   function */
	for( i = 0; i < NO_CACHED_QUERIES; i++ )
		{
		SQLSetStmtAttr( dbmsInfo->hStmt[ i ], SQL_ATTR_CURSOR_TYPE,
						( SQLPOINTER ) SQL_CURSOR_FORWARD_ONLY,
						SQL_IS_INTEGER );
		if( options == CRYPT_KEYOPT_READONLY )
			SQLSetStmtAttr( dbmsInfo->hStmt[ i ], SQL_ATTR_CONCURRENCY,
							( SQLPOINTER ) SQL_CONCUR_READ_ONLY,
							SQL_IS_INTEGER );
		SQLSetStmtAttr( dbmsInfo->hStmt[ i ], SQL_ATTR_NOSCAN,
						( SQLPOINTER ) SQL_NOSCAN_ON, SQL_IS_INTEGER );
		}

	/* Get various driver and data source-specific information that we may
	   need later on */
	status = getDatatypeInfo( dbmsInfo, featureFlags );
	if( cryptStatusError( status ) )
		{
		closeDatabase( dbmsInfo );
		return( status );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Database Read Routines							*
*																			*
****************************************************************************/

/* Fetch data from a query */

static int fetchData( const SQLHSTMT hStmt, char *data,
					  int *dataLength, const int maxLength,
					  const DBMS_QUERY_TYPE queryType,
					  DBMS_STATE_INFO *dbmsInfo )
	{
	const SQLSMALLINT dataType = ( dbmsInfo->hasBinaryBlobs ) ? \
								 SQL_C_BINARY : SQL_C_CHAR;
	SQLRETURN sqlStatus;
	SQLUINTEGER length;

	/* Clear return value */
	if( dataLength != NULL )
		*dataLength = 0;

	/* Get the results of the transaction */
	sqlStatus = SQLFetch( hStmt );
	if( !sqlStatusOK( sqlStatus ) )
		{
		/* If the fetch status is SQL_NO_DATA, indicating the end of the
		   result set, we handle it specially since some drivers only return
		   the basic error code and don't provide any further diagnostic
		   info to be fetched by SQLGetDiagRec() */
		if( sqlStatus == SQL_NO_DATA )
			{
			strcpy( dbmsInfo->errorMessage, "No data found" );
			return( CRYPT_ERROR_NOTFOUND );
			}
		return( getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
							  CRYPT_ERROR_READ ) );
		}

	/* If we're just doing a presence check, we don't bother fetching data */
	if( queryType == DBMS_QUERY_CHECK )
		return( CRYPT_OK );

	/* Read the data */
	sqlStatus = SQLGetData( hStmt, 1, dataType, data, maxLength, &length );
	if( !sqlStatusOK( sqlStatus ) )
		return( getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
							  CRYPT_ERROR_READ ) );
	*dataLength = ( int ) length;
	return( CRYPT_OK );
	}

/* Perform a transaction that returns information */

static int performQuery( DBMS_STATE_INFO *dbmsInfo, const char *command,
						 char *data, int *dataLength, const char *boundData,
						 const int boundDataLength, const time_t boundDate,
						 const DBMS_CACHEDQUERY_TYPE queryEntry,
						 const DBMS_QUERY_TYPE queryType )
	{
	/* We have to explicitly set the maximum length indicator because some
	   sources will helpfully zero-pad the data to the maximum indicated size,
	   which is smaller for binary data */
	const int maxLength = dbmsInfo->hasBinaryBlobs ? \
						  MAX_CERT_SIZE : MAX_QUERY_RESULT_SIZE;
	const SQLHSTMT hStmt = dbmsInfo->hStmt[ queryEntry ];
	TIMESTAMP_STRUCT timeStamp;
	SQLINTEGER lengthInfo;
	SQLRETURN sqlStatus;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_STATE_INFO ) ) );
	assert( ( data == NULL && dataLength == NULL ) || \
			isWritePtr( dataLength, sizeof( int ) ) );
	assert( ( boundData == NULL && boundDataLength == 0 ) || \
			( boundDate == 0 ) );

	/* Clear return value */
	if( dataLength != NULL )
		*dataLength = 0;

	/* If we're starting a new query, handle the query initialisation and
	   parameter binding */
	if( queryType == DBMS_QUERY_START || \
		queryType == DBMS_QUERY_CHECK || \
		queryType == DBMS_QUERY_NORMAL )
		{
		/* Prepare the query for execution if necessary */
		if( queryEntry != DBMS_CACHEDQUERY_NONE && \
			!dbmsInfo->hStmtPrepared[ queryEntry ] )
			{
			char query[ MAX_SQL_QUERY_SIZE ];

			convertQuery( dbmsInfo, query, command );
			sqlStatus = SQLPrepare( hStmt, query, SQL_NTS );
			if( !sqlStatusOK( sqlStatus ) )
				return( getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
									  CRYPT_ERROR_READ ) );
			dbmsInfo->hStmtPrepared[ queryEntry ] = TRUE;
			}

		/* Bind in any query parameters that may be required */
		status = bindParameters( hStmt, boundData, boundDataLength,
								 boundDate, &timeStamp, &lengthInfo,
								 dbmsInfo, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	switch( queryType )
		{
		case DBMS_QUERY_START:
			assert( boundDate == 0 );

			/* Execute the query */
			if( queryEntry == DBMS_CACHEDQUERY_NONE )
				{
				char query[ MAX_SQL_QUERY_SIZE ];

				convertQuery( dbmsInfo, query, command );
				sqlStatus = SQLExecDirect( hStmt, query, SQL_NTS );
				}
			else
				sqlStatus = SQLExecute( hStmt );
			if( !sqlStatusOK( sqlStatus ) )
				return( getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
									  CRYPT_ERROR_READ ) );

			/* If we're starting an ongoing query with results to be fetched
			   later, we're done */
			if( data == NULL )
				return( CRYPT_OK );

			/* Drop through to fetch the first set of results */

		case DBMS_QUERY_CONTINUE:
			assert( maxLength > 16 && isWritePtr( data, maxLength ) );

			/* We're in the middle of a continuing query, fetch the next set
			   of results.  If we've run out of results (indicated by a not-
			   found status) we explicitly signal to the caller that the
			   query has completed */
			status = fetchData( dbmsInfo->hStmt[ queryEntry ], data,
								dataLength, maxLength, DBMS_QUERY_CONTINUE,
								dbmsInfo );
			return( cryptStatusOK( status ) ? CRYPT_OK : \
					( status == CRYPT_ERROR_NOTFOUND ) ? \
					CRYPT_ERROR_COMPLETE : status );

		case DBMS_QUERY_CANCEL:
			/* Cancel any outstanding requests to clear the hStmt ready for
			   re-use */
			SQLCloseCursor( dbmsInfo->hStmt[ queryEntry ] );
			return( CRYPT_OK );

		case DBMS_QUERY_CHECK:
		case DBMS_QUERY_NORMAL:
			/* Only return a maximum of a single row in response to a point
			   query.  This is a simple optimisation to ensure that the
			   database client doesn't start sucking across huge amounts of
			   data when it's not necessary */
			SQLSetStmtAttr( hStmt, SQL_ATTR_MAX_ROWS, ( SQLPOINTER ) 1,
							SQL_IS_INTEGER );

			/* Execute the SQL statement and fetch the results */
			if( queryEntry == DBMS_CACHEDQUERY_NONE )
				{
				char query[ MAX_SQL_QUERY_SIZE ];

				convertQuery( dbmsInfo, query, command );
				sqlStatus = SQLExecDirect( hStmt, query, SQL_NTS );
				}
			else
				sqlStatus = SQLExecute( hStmt );
			if( sqlStatusOK( sqlStatus ) )
				{
				status = fetchData( hStmt, data, dataLength, maxLength,
									queryType, dbmsInfo );
				SQLCloseCursor( hStmt );
				}
			else
				status = getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
									   CRYPT_ERROR_READ );

			/* Reset the statement handle's multi-row result handling */
			SQLSetStmtAttr( hStmt, SQL_ATTR_MAX_ROWS, ( SQLPOINTER ) 0,
							SQL_IS_INTEGER );
			return( status );

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );
	}

/* Fetch extended error information from the database state info */

static void performErrorQuery( DBMS_STATE_INFO *dbmsInfo, int *errorCode,
							   char *errorMessage )
	{
	assert( isWritePtr( dbmsInfo, sizeof( DBMS_STATE_INFO ) ) );
	assert( isWritePtr( errorCode, sizeof( int ) ) );
	assert( isWritePtr( errorMessage, MAX_ERRMSG_SIZE ) );

	*errorCode = dbmsInfo->errorCode;
	strcpy( errorMessage, dbmsInfo->errorMessage );
	}

/****************************************************************************
*																			*
*						 	Database Write Routines							*
*																			*
****************************************************************************/

/* Perform a transaction that updates the database without returning any
   data */

static int performUpdate( DBMS_STATE_INFO *dbmsInfo, const char *command,
						  const void *boundData, const int boundDataLength,
						  const time_t boundDate,
						  const DBMS_UPDATE_TYPE updateType )
	{
	TIMESTAMP_STRUCT timeStamp;
	const SQLHSTMT hStmt = dbmsInfo->hStmt[ 0 ];
	SQLINTEGER lengthInfo;
	SQLRETURN sqlStatus;
	int status = CRYPT_OK;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_STATE_INFO ) ) );

	/* If we're aborting a transaction, roll it back, re-enable autocommit,
	   and clean up */
	if( updateType == DBMS_UPDATE_ABORT )
		{
		SQLEndTran( SQL_HANDLE_DBC, dbmsInfo->hDbc, SQL_ROLLBACK );
		SQLSetConnectAttr( dbmsInfo->hDbc, SQL_ATTR_AUTOCOMMIT,
						   ( SQLPOINTER ) SQL_AUTOCOMMIT_ON,
						   SQL_IS_UINTEGER );
		return( CRYPT_OK );
		}

	/* If it's the start of a transaction, turn autocommit off */
	if( updateType == DBMS_UPDATE_BEGIN )
		SQLSetConnectAttr( dbmsInfo->hDbc, SQL_ATTR_AUTOCOMMIT,
						   ( SQLPOINTER ) SQL_AUTOCOMMIT_OFF,
						   SQL_IS_UINTEGER );

	/* Bind in any necessary parameters to the hStmt.  For the older (and
	   often somewhat flaky) Win16 ODBC 1.x/2.x drivers the binding process
	   was unlike the behaviour mentioned in the ODBC documentation, which
	   claimed that SQLExecDirect() would return SQL_NEED_DATA if it found a
	   parameter marker.  Instead, we have to bind the parameters before
	   calling SQLExecDirect() and it reads them from the bound location as
	   required.  In addition an older version of the ODBC spec required
	   that the cbColDef value never exceed SQL_MAX_MESSAGE_LENGTH, however
	   this was defined to be 512 bytes which meant that we couldn't add
	   most certs of any real complexity or with keys > 1K bits.  The
	   workaround was to pass in the actual data length here instead.  This
	   worked for all ODBC drivers tested.

	   For any newer Win32 ODBC 3.x drivers this isn't a problem any more,
	   so we use the mechanism described in the docs, leaving the older
	   alternative as an option if it's ever needed */
	status = bindParameters( hStmt, boundData, boundDataLength,
							 boundDate, &timeStamp, &lengthInfo,
							 dbmsInfo, FALSE );
	if( cryptStatusError( status ) )
		return( status );
#ifdef ODBC1x
	if( boundData != NULL )
		{
		dbmsInfo->cbBlobLength = SQL_LEN_DATA_AT_EXEC( boundDataLength );
		SQLBindParameter( hStmt, paramNo++, SQL_PARAM_INPUT,
						  dbmsInfo->hasBinaryBlobs ? SQL_C_BINARY : SQL_C_CHAR,
						  dbmsInfo->blobType, boundDataLength, 0,
						  ( SQLPOINTER ) 6, 0, &dbmsInfo->cbBlobLength );
		}
#endif /* ODBC1x */

	/* Execute the command/hStmt as appropriate */
	if( command == NULL )
		sqlStatus = SQLExecute( hStmt );
	else
		{
		char query[ MAX_SQL_QUERY_SIZE ];

		convertQuery( dbmsInfo, query, command );
		sqlStatus = SQLExecDirect( hStmt, query, SQL_NTS );
		}
#ifdef ODBC1x
	if( sqlStatus == SQL_NEED_DATA )
		{
		SQLPOINTER pToken;

		/* Add the key data and perform a dummy SQLParamData() call to tell
		   the ODBC driver that we've finished with the operation */
		SQLParamData( hStmt, &pToken );
		sqlStatus = SQLPutData( hStmt, ( SQLPOINTER ) boundData,
								boundDataLength );
		if( sqlStatusOK( sqlStatus ) )
			sqlStatus = SQLParamData( hStmt, &pToken );
		}
#endif /* ODBC1x */
	if( !sqlStatusOK( sqlStatus ) )
		{
		/* The return status from a delete operation can be reported in
		   several ways at the whim of the driver.  Some drivers always
		   report success even though nothing was found to delete (more
		   common in ODBC 2.x drivers, see the code further on for the
		   handling for this).  Others report a failure to delete anything
		   with an SQL_NO_DATA status (more common in ODBC 3.x drivers).
		   For this case we convert the overall status to a
		   CRYPT_ERROR_NOTFOUND and update the sqlStatus as required if we
		   need to continue */
		if( sqlStatus == SQL_NO_DATA && command != NULL && \
			!strCompare( command, "DELETE", 6 ) )
			{
			status = CRYPT_ERROR_NOTFOUND;
			if( updateType != DBMS_UPDATE_COMMIT )
				return( status );
			}
		else
			{
			/* If we hit an error at this point we can only exit if we're
			   not finishing a transaction.  If we are, the commit turns
			   into an abort further down */
			status = getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
								   CRYPT_ERROR_WRITE );
			if( updateType != DBMS_UPDATE_COMMIT )
				return( status );
			}
		}
	else
		/* If we're performing a delete, the operation will succeed even
		   though nothing was found to delete,  so we make sure that we
		   actually changed something */
		if( command != NULL && !strCompare( command, "DELETE", 6 ) )
			{
			SQLUINTEGER rowCount;

			SQLRowCount( hStmt, &rowCount );
			if( rowCount <= 0 )
				status = CRYPT_ERROR_NOTFOUND;
			}

	/* If it's the end of a transaction, commit the transaction and turn
	   autocommit on again */
	if( updateType == DBMS_UPDATE_COMMIT )
		{
		SQLRETURN sqlStatus;

		/* If we've had a failure before this point, abort, otherwise
		   commit.  The SQLSMALLINT cast is necessary in some development
		   environments (although spurious) */
		sqlStatus = SQLEndTran( SQL_HANDLE_DBC, dbmsInfo->hDbc,
								( SQLSMALLINT  ) \
								( cryptStatusError( status ) ? \
								  SQL_ROLLBACK : SQL_COMMIT ) );
		if( dbmsInfo->transactIsDestructive )
			{
			int i;

			/* If transactions are destructive for this back-end, invalidate
			   all prepared statements */
			for( i = 0; i < NO_CACHED_QUERIES; i++ )
				dbmsInfo->hStmtPrepared[ i ] = FALSE;
			}
		SQLSetConnectAttr( dbmsInfo->hDbc, SQL_ATTR_AUTOCOMMIT,
						   ( SQLPOINTER ) SQL_AUTOCOMMIT_ON,
						   SQL_IS_UINTEGER );
		if( cryptStatusOK( status ) && !sqlStatusOK( sqlStatus ) )
			status = getErrorInfo( dbmsInfo, SQL_ERRLVL_STMT, hStmt,
								   CRYPT_ERROR_WRITE );
		}

	return( status );
	}

#ifndef USE_RPCAPI

int initDispatchODBC( DBMS_INFO *dbmsInfo )
	{
	dbmsInfo->openDatabaseBackend = openDatabase;
	dbmsInfo->closeDatabaseBackend = closeDatabase;
	dbmsInfo->performUpdateBackend = performUpdate;
	dbmsInfo->performQueryBackend = performQuery;
	dbmsInfo->performErrorQueryBackend = performErrorQuery;

	return( CRYPT_OK );
	}
#else

/* Pull in the shared database RPC routines, renaming the generic dispatch
   function to the ODBC-specific one which is called directly by the
   marshalling code */

#define processCommand( stateInfo, buffer ) \
		odbcProcessCommand( stateInfo, buffer )
#include "dbx_rpc.c"

#endif /* !USE_RPCAPI */

#endif /* USE_ODBC */
