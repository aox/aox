/****************************************************************************
*																			*
*						cryptlib Oracle Mapping Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* TODO:

  - All of the functions are only about 98% complete (I lost the use of the
	Oracle system before I was finished).
  - The code could be rewritten to use dlopen() in a similar manner to the
	ODBC linking under Windows.
*/

#include <stdio.h>
#include <string.h>
#include "crypt.h"
#include "keyset/keyset.h"

#ifdef USE_ORACLE

/* Get information on an Oracle error */

static void getErrorInfo( DBMS_STATE_INFO *dbmsInfo )
	{
	sword length;

	length = oerhms( &dbmsInfo->lda, dbmsInfo->cda.rc,
					 dbmsInfo->errorMessage, MAX_ERRMSG_SIZE );
	dbmsInfo->errorCode = dbmsInfo->cda.rc;
	}

/* Convery a query from generic SQL into the Oracle-specific format */

static void convertQuery( char *query, const char *command )
	{
	assert( command != NULL );
	strcpy( query, command );
	if( !strncmp( command, "CREATE TABLE", 12 ) )
		{
		char *blobName = strstr( query, " BLOB " );

		if( blobName != NULL )
			{
			memmove( blobName + 10, blobName + 6, strlen( blobName + 6 ) );
			strncpy( blobName, " LONG RAW ", 10 );
			}
		}
	}

/* Open and close a connection to an Oracle server */

static int openDatabase( DBMS_STATE_INFO *dbmsInfo, const char *name,
						 const int options, int *featureFlags )
	{
	int status;

	UNUSED( options );

	/* Connect to the Oracle server and open a cursor */
	status = orlon( &dbmsInfo->lda, dbmsInfo->hda, name, -1,
					( char * ) password, -1, 0 );
	if( status )
		{
		getErrorInfo( dbmsInfo );
		if( !dbmsInfo->errorCode )
			{
			/* Occasionally funny things can happen when we try to log on,
			   for example if the Oracle client has a resource problem
			   orlon() will fail with an error code but oerhms() will return
			   a non-error status, so if there's no apparent error we set
			   the error code to the orlon() return code and put a special
			   string in the buffer to tell the caller what's wrong */
			dbmsInfo->errorCode = status;
			strcpy( dbmsInfo->errorMessage, "ORA-????: resource error "
					"connecting to database, error text cannot be\n"
					"generated because no connection is established.  See "
					"error code for more\ninformation" );
			}
		return( CRYPT_ERROR_OPEN );
		}
	if( oopen( &dbmsInfo->cda, &dbmsInfo->lda, 0, -1, -1, 0, -1 ) )
		{
		getErrorInfo( dbmsInfo );
		ologof( &dbmsInfo->lda );
		return( CRYPT_ERROR_OPEN );
		}

	/* Turn off auto-commit (this is the default anyway) */
	ocof( &dbmsInfo->lda );

	/* Oracle can handle binary blobs */
	*featureFlags = DBMS_HAS_BINARYBLOBS;

	return( CRYPT_OK );
	}

static void closeDatabase( DBMS_STATE_INFO *dbmsInfo )
	{
	oclose( &dbmsInfo->cda );
	ologof( &dbmsInfo->lda );
	}

/* Perform a transaction which updates the database without returning any
   data */

static int performUpdate( DBMS_STATE_INFO *dbmsInfo, const char *command,
						  const void *boundData, const int boundDataLength,
						  const time_t boundDate,
						  const DBMS_UPDATE_TYPE updateType )
	{
	char query[ MAX_SQL_QUERY_SIZE ];

	convertQuery( query, command );

/* !!!! Need to bind in boundData and date if necessary as dbxodbc.c !!!! */

	/* Perform a deferred parse of the SQL statement */
	if( oparse( &dbmsInfo->cda, query, -1, 1, 1 ) )
		{
		getErrorInfo( dbmsInfo );
		return( CRYPT_ERROR_WRITE );
		}

	/* Since the input is coded as part of the command, we don't need to bind
	   any input variables so we move directly to executing the statement */
	if( oexec( &dbmsInfo->cda ) || dbmsInfo->cda.rc != 0 )
		{
		getErrorInfo( dbmsInfo );
		return( CRYPT_ERROR_WRITE );
		}

	return( CRYPT_OK );
	}

/* Perform a transaction which checks for the existence of an object */

static int performCheck( DBMS_STATE_INFO *dbmsInfo, const char *command )
	{
	ub2 rlen;
	int count, status;

	/* Perform a deferred parse of the SQL statement */
	if( oparse( &dbmsInfo->cda, ( char * ) command, -1, 1, 1 ) )
		{
		getErrorInfo( dbmsInfo );
		return( CRYPT_ERROR_READ );
		}

	/* We're checking whether a given name or key ID exists by counting the
	   number of occurrences */
	if( odefin( &dbmsInfo->cda, 1, ( ub1 * ) &count, sizeof( int ), SQLT_INT,
				-1, NULL, 0, -1, -1, &rlen, NULL ) )
		{
		getErrorInfo( dbmsInfo );
		return( CRYPT_ERROR_READ );
		}

	/* Since the input is coded as part of the command, we don't need to bind
	   any input variables so we move directly to executing the statement and
	   fetching the result */
	status = oexfet( &dbmsInfo->cda, 1, 0, 0 );
	if( status == -904 || status == -942 )
		/* If the table or column doesn't exist, return the appropriate error
		   code */
		return( CRYPT_ERROR_NOTFOUND );
	if( status )
		{
		getErrorInfo( dbmsInfo );
		return( CRYPT_ERROR_READ );
		}

	return( count );
	}

/* Perform a transaction which returns information */

static int performQuery( DBMS_STATE_INFO *dbmsInfo, const char *command,
						 char *data, int *dataLength,
						 const DBMS_QUERY_TYPE queryType )
	{
	ub2 rlen;
	int status;

	/* If this assertion triggers, you need to add handling for the other
	   query types.  See keyset/keyset.h and keyset/dbxodbc.c for guidance */
	assert( queryType == DBMS_QUERY_NORMAL );

	/* Perform a deferred parse of the SQL statement */
	if( oparse( &dbmsInfo->cda, ( char * ) command, -1, 1, 1 ) )
		{
		getErrorInfo( dbmsInfo );
		return( CRYPT_ERROR_READ );
		}

	/* We're reading the key data.  Since a VARCHAR can be rather long and we
	   don't pass in a full-length buffer, we set the indicator pointer to
	   NULL to stop Oracle telling us that there could be up to 32K of output
	   even through the buffer we're supplying is only a few K */
	if( odefin( &dbmsInfo->cda, 1, data, MAX_CERT_SIZE, SQLT_STR,
				-1, NULL, 0, -1, -1, &rlen, NULL ) )
		{
		getErrorInfo( dbmsInfo );
		return( CRYPT_ERROR_READ );
		}

	/* Since the input is coded as part of the command, we don't need to bind
	   any input variables so we move directly to executing the statement and
	   fetching the result */
	if( oexfet( &dbmsInfo->cda, 1, 0, 0 ) )
		{
		/* If the requested record wasn't found, handle the error
		   specially */
		if( dbmsInfo->cda.rc == 1403 )
			return( CRYPT_ERROR_NOTFOUND );

		getErrorInfo( dbmsInfo );
		return( CRYPT_ERROR_READ );
		}

	/* The returned length is the length of the field, not the length of the
	   data element, so we use strlen() to get the exact length */
	*dataLength = strlen( data );
	return( CRYPT_OK );
	}

/* Fetch extended error information from the database state info */

static void performErrorQuery( DBMS_STATE_INFO *dbmsInfo, int *errorCode,
							   char *errorMessage )
	{
	*errorCode = dbmsInfo->errorCode;
	strcpy( errorMessage, dbmsInfo->errorMessage );
	}

/* Pull in the shared database RPC routines */

#include "dbx_rpc.c"

#endif /* USE_ORACLE */
