/****************************************************************************
*																			*
*						cryptlib Postgres Mapping Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* TODO:

  - All of the functions are only about 98% complete (I lost the use of the
	Postgres systems before I was finished).
  - The code could be rewritten to use dlopen() in a similar manner to the
	ODBC linking under Windows.
*/

#include <stdio.h>
#include <string.h>
#include "crypt.h"
#include "keyset/keyset.h"

/****************************************************************************
*																			*
*							Unix Database Access Functions					*
*																			*
****************************************************************************/

#ifdef USE_POSTGRES

/* Postgres has a few odd variations on standard SQL.  It implements a number
   of SQL primitives as inbuilt functions rather than proper primitives,
   which means they're case-sensitive.  In order for them to be recognised we
   have to convert them to lowercase before we can execute them (the only one
   we actually use is COUNT).  In addition, for CREATE INDEX statements it
   requires a USING clause (this may be a bug in the 1.08 parser rather than
   a feature, but it also allows us to specify the use of a hash index which
   is the best choice for the guaranteed-unique values we're building the
   index on).

   The following function looks for these special cases and converts the
   query into the format required by Postgres */

static void convertQuery( char *query, const char *command )
	{
	char *strPtr;

	strcpy( query, command );
	if( !strncmp( command, "CREATE TABLE", 12 ) )
		{
		char *blobName = strstr( query, " BLOB " );

		if( blobName != NULL )
			{
			memmove( blobName + 15, blobName + 6, strlen( blobName + 6 ) );
			strncpy( blobName, " VARCHAR(2048) ", 15 );
			}
		}
	if( ( strPtr = strstr( query, "COUNT" ) ) != NULL )
		strncpy( strPtr, "count", 5 );
	if( ( strPtr = strstr( query, "CREATE INDEX" ) ) != NULL )
		{
		strPtr = strchr( query, '(' );
		memmove( strPtr + 11, strPtr, strlen( strPtr ) + 1 );
		strncpy( strPtr, "USING hash ", 11 );
		strPtr = strchr( query, ')' );
		memmove( strPtr + 9, strPtr, strlen( strPtr ) + 1 );
		strncpy( strPtr, " text_ops", 9 );
		}
	}

/* Get information on a Postgres error */

static int getErrorInfo( DBMS_STATE_INFO *dbmsInfo, const int defaultStatus )
	{
	/* Postgres has an annoying non-unified error indication system in which
	   an error code can mean different things depending on what the current
	   usage context is, so we need to get error information in a context-
	   specific manner */
	if( dbmsInfo->pgResult )
		{
		strncpy( dbmsInfo->errorMessage, PQcmdStatus( dbmsInfo->pgResult ),
				 MAX_ERRMSG_SIZE - 1 );
		dbmsInfo->errorCode = PQresultStatus( dbmsInfo->pgResult );

		/* Now that we've got the information, clear the result */
		PQclear( dbmsInfo->pgResult );
		dbmsInfo->pgResult = NULL;
		}
	else
		{
		strncpy( dbmsInfo->errorMessage, PQerrorMessage( dbmsInfo->pgConnection ),
				 MAX_ERRMSG_SIZE - 1 );
		dbmsInfo->errorCode = PQstatus( dbmsInfo->pgConnection );

		/* At the PGconn level, the only information Postgres can return is
		   "connection OK" or "connection bad", so we have to pick apart the
		   returned error message to find out what went wrong.  This is
		   pretty nasty since it may break if the error messages are ever
		   changed */
		if( strstr( dbmsInfo->errorMessage, "no such class" ) != NULL || \
			strstr( dbmsInfo->errorMessage, "not found" ) != NULL )
			{
			dbmsInfo->errorMessage[ 0 ] = '\0';
			return( CRYPT_ERROR_NOTFOUND );
			}
		}
	dbmsInfo->errorMessage[ MAX_ERRMSG_SIZE - 1 ] = '\0';

	return( defaultStatus );
	}

/* Open and close a connection to a Postgres server */

static int openDatabase( DBMS_STATE_INFO *dbmsInfo, const char *name,
						 const int options, int *featureFlags )
	{
	int status;

	UNUSED( user );
	UNUSED( password );
	UNUSED( options );

	/* Connect to the Postgres server */
	dbmsInfo->pgConnection = PQsetdb( server, NULL, NULL, NULL, name );
	if( PQstatus( dbmsInfo->pgConnection ) == CONNECTION_BAD )
		{
		PQfinish( dbmsInfo->pgConnection );
		dbmsInfo->pgConnection = NULL;
		return( CRYPT_ERROR_OPEN );
		}
	*featureFlags = DBMS_HAS_NONE;

	return( CRYPT_OK );
	}

static void closeDatabase( DBMS_STATE_INFO *dbmsInfo )
	{
	PQfinish( dbmsInfo->pgConnection );
	dbmsInfo->pgConnection = NULL;
	}

/* Perform a transaction which updates the database without returning any
   data */

static int performUpdate( DBMS_STATE_INFO *dbmsInfo, const char *command,
						  const void *boundData, const int boundDataLength,
						  const time_t boundDate )
	{
	char query[ MAX_SQL_QUERY_SIZE ];

	assert( boundData == NULL );

/* !!!! Need to convert date data, see dbxmysql.c !!!! */

	/* Submit the query to the Postgres server */
	convertQuery( query, command );
	dbmsInfo->pgResult = PQexec( dbmsInfo->pgConnection, query );
	if( dbmsInfo->pgResult == NULL )
		{
		DEBUG( puts( "performUpdate:PQexec() failed" ) );
		return( getErrorInfo( dbmsInfo, CRYPT_ERROR_WRITE ) );
		}

	/* Since this doesn't return any results, all we need to do is clear the
	   result to free the PGresult storage */
	PQclear( dbmsInfo->pgResult );
	dbmsInfo->pgResult = NULL;

	return( CRYPT_OK );
	}

/* Perform a transaction which returns information */

static int performQuery( DBMS_STATE_INFO *dbmsInfo, const char *command,
						 char *data, int *dataLength,
						 const DBMS_QUERY_TYPE queryType )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int status = CRYPT_OK;

	/* If this assertion triggers, you need to add handling for the other
	   query types.  See keyset/keyset.h and keyset/dbxodbc.c for guidance */
	assert( queryType == DBMS_QUERY_NORMAL );

	/* Submit the query to the Postgres server */
	convertQuery( query, command );
	dbmsInfo->pgResult = PQexec( dbmsInfo->pgConnection, query );
	if( dbmsInfo->pgResult == NULL )
		return( getErrorInfo( dbmsInfo, CRYPT_ERROR_READ ) );

	/* Make sure the query completed successfully */
	if( PQresultStatus( dbmsInfo->pgResult ) != PGRES_TUPLES_OK )
		{
		status = getErrorInfo( dbmsInfo, CRYPT_ERROR_NOTFOUND );
		PQclear( dbmsInfo->pgResult );
		dbmsInfo->pgResult = NULL;
		return( status );
		}

	/* Get the result of the query and clear the result */
/*	*dataLength = PQgetlength( dbmsInfo->pgResult, 0, 0 ); */
/* !!!! Is this the right function !!!! */
	*dataLength = PQfsize( dbmsInfo->pgResult, 0 );
	if( *dataLength > MAX_CERT_SIZE )
		{
		*dataLength = 0;
		status = CRYPT_ERROR_OVERFLOW;
		}
	else
		strcpy( data, PQgetvalue( dbmsInfo->pgResult, 1, 1 ) );
	PQclear( dbmsInfo->pgResult );
	dbmsInfo->pgResult = NULL;

	return( CRYPT_OK );
	}

/* Perform a transaction which checks for the existence of an object */

static int performCheck( DBMS_STATE_INFO *dbmsInfo, const char *command )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int count, status;

	/* Submit the query to the Postgres server */
	convertQuery( query, command );
	dbmsInfo->pgResult = PQexec( dbmsInfo->pgConnection, query );
	if( dbmsInfo->pgResult == NULL )
		return( getErrorInfo( dbmsInfo, CRYPT_ERROR_READ ) );

	/* Check whether the query completed successfully */
	status = PQresultStatus( dbmsInfo->pgResult );
	if( status != PGRES_TUPLES_OK )
		status = getErrorInfo( dbmsInfo, CRYPT_ERROR_NOTFOUND );
	else
		status = CRYPT_OK;
	PQclear( dbmsInfo->pgResult );
	dbmsInfo->pgResult = NULL;
	return( status );
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

#endif /* USE_POSTGRES */
