/****************************************************************************
*																			*
*						 cryptlib MySQL Mapping Routines					*
*						Copyright Peter Gutmann 1997-2001					*
*																			*
****************************************************************************/

/* TODO:

  - This is mostly a direct conversion of the mSQL code to MySQL.  Since I
	don't run MySQL I haven't been able to check the code much.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef INC_CHILD
  #include "../crypt.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
#endif /* INC_CHILD */

/****************************************************************************
*																			*
*							MySQL Database Access Functions					*
*																			*
****************************************************************************/

#ifdef USE_MYSQL

/* Translate the SQL into the MySQL variant as appropriate */

static void convertQuery( char *query, const char *command )
	{
	BOOLEAN uniqueIndex = FALSE;

	assert( command != NULL );
	strcpy( query, command );

	/* If it's a CREATE TABLE command, rewrite the blob and date types to
	   the appropriate values for the database backend */
	if( !strncmp( command, "CREATE TABLE", 12 ) )
		{
		char *placeholderPtr;

		if( ( placeholderPtr = strstr( query, " BLOB" ) ) != NULL )
			/* Although MySQL supports blobs, the mechanism for handling
			   them is clunky to say the least (they have to be represented
			   in a kind of quoted-printable form since MySQL doesn't handle
			   bound variables) so we fall back to using the non-blob
			   alternative which is easier */
			memcpy( placeholderPtr, " TEXT", 5 );
		if( ( placeholderPtr = strstr( query, " DATETIME" ) ) != NULL )
			{
			/* Open up a gap and replace the date name placeholder with the
			   MySQL date name */
			memcpy( placeholderPtr, " DATE", 5 );
			memmove( placeholderPtr + 5, placeholderPtr + 9,
					 strlen( placeholderPtr + 9 ) + 1 );
			}
		}
	}

/* Bind a date into a query, which involves manually translating it into the
   DATETIME data because of MySQL's lack of support for bound variables */

#define DATETIME_SIZE		14

static int bindDate( char *query, const time_t boundDate )
	{
	struct tm *timeInfo = gmtime( &boundDate );
	char *datePtr = strchr( query, '?' );
	int length = strlen( query ), ch;

	assert( timeInfo != NULL );
	assert( datePtr != NULL );

	/* If we can't add the date information, return a data overflow
	   error */
	if( length > MAX_SQL_QUERY_SIZE - DATETIME_SIZE )
		return( CRYPT_ERROR_OVERFLOW );

	/* Poke the date info into the query string.  This encodes the data in
	   the ISO 8601 format, which allows comparisons like < and > to work
	   properly.  When calculating the size, we use DATETIME_SIZE + 2 to
	   account for the extra ''s needed to demarcate the date string */
	memmove( datePtr + DATETIME_SIZE + 1, datePtr,
			 strlen( datePtr ) + 1 );
	ch = datePtr[ DATETIME_SIZE + 2 ];
	sprintf( datePtr, "'%04d%02d%02d%02d%02d%02d'",
			 timeInfo->tm_year + 1900, timeInfo->tm_mon + 1,
			 timeInfo->tm_mday, timeInfo->tm_hour, timeInfo->tm_min,
			 timeInfo->tm_sec );
	datePtr[ DATETIME_SIZE + 2 ] = ch;	/* Restore value zapped by '\0' */

	return( CRYPT_OK );
	}

/* Get information on a MySQL error */

static int getErrorInfo( DBMS_STATE_INFO *dbmsInfo, const int defaultStatus )
	{
	const char *mysqlErrorMsg = mysql_error( dbmsInfo->connection );
	int length = min( strlen( mysqlErrorMsg ), MAX_ERRMSG_SIZE - 1 );

	/* MySQL returns error information as a static string via mysqlErrMsg().
	   Because we can't get a real error code, we have to pick apart the
	   error string to provide more information on certain types of error */
	strncpy( dbmsInfo->errorMessage, mysqlErrorMsg, length );
	dbmsInfo->errorMessage[ length ] = '\0';
	dbmsInfo->errorCode = mysql_errno( dbmsInfo->connection );

	/* The only information we can get from mysqlSelectDB() and mysqlQuery()
	   is "OK" or "not OK" (and, in 2.x, the number of items returned for
	   mysqlQuery()), so we have to pick apart the returned error message to
	   find out what went wrong.  This is pretty nasty since it may break if
	   the error messages are ever changed */
	if( ( !strncmp( dbmsInfo->errorMessage, "Table", 5 ) && \
		  !strncmp( dbmsInfo->errorMessage + length - 6, "exists", 6 ) ) )
		return( CRYPT_ERROR_DUPLICATE );

	return( defaultStatus );
	}

/* Open and close a connection to a MySQL server */

static int openDatabase( DBMS_STATE_INFO *dbmsInfo, const char *name,
						 const int options, int *featureFlags )
	{
	MYSQL *mysql;
	char *hostNamePtr = ( char * ) host;
	int status = -1;

	UNUSED( options );

	/* Connect to the MySQL server and select the database */
	if( host == NULL )
		hostNamePtr = "localhost";	/* Connect to default host */
	mysql = mysql_init( NULL );
	dbmsInfo->connection = mysql_real_connect( mysql, hostNamePtr, user,
											   password, name, 0, NULL, 0 );
	if( dbmsInfo->connection == NULL )
		{
		dbmsInfo->connection = mysql;
		getErrorInfo( dbmsInfo, CRYPT_ERROR_OPEN );
		dbmsInfo->connection = NULL;
		mysql_close( mysql );		/* Free the MYSQL structure */
		return( CRYPT_ERROR_OPEN );
		}

	/* Set some options to improve performance.  We set the select limit to
	   1 (since we're only ever going to retrieve one row), and tell the
	   server to abort if a select would take a very long time (this
	   shouldn't have any effect on anything created by cryptlib, but it's
	   worth doing anyway for general bulletproofing) */
	mysql_query( dbmsInfo->connection, "SET SQL_SELECT_LIMIT=1" );
	mysql_query( dbmsInfo->connection, "SET SQL_BIG_SELECTS=1" );

	/* Return database backend-specific information to the caller */
	*featureFlags = DBMS_HAS_NONE;

	return( CRYPT_OK );
	}

static void closeDatabase( DBMS_STATE_INFO *dbmsInfo )
	{
	mysql_close( dbmsInfo->connection );
	dbmsInfo->connection = NULL;
	}

/* Perform a transaction which updates the database without returning any
   data */

static int performUpdate( DBMS_STATE_INFO *dbmsInfo, const char *command,
						  const void *boundData, const int boundDataLength,
						  const time_t boundDate,
						  const DBMS_UPDATE_TYPE updateType )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int status;

	/* If we're aborting a transaction, tell the server and exit (given
	   MySQL's current non-transaction handling this isn't going to do much,
	   but it's better than nothing) */
	if( updateType == DBMS_UPDATE_ABORT )
		{
		mysql_query( dbmsInfo->connection, "ROLLBACK" );
		return( CRYPT_OK );
		}

	/* If it's the start of a transaction, tell the server.  The MySQL
	   manual is somewhat evasive as to just how effective this type of
	   pseudo-transaction management really is, presumably it just holds the
	   data in memory until a commit or rollback command is sent, however
	   it must do some sort of lazy commit because it can't hold infinite
	   amounts of data in memory forever.  In any case it shouldn't be a
	   problem for cryptlib because it only sends in small data quantities
	   all in one lot */
	if( updateType == DBMS_UPDATE_BEGIN )
		{
		mysql_query( dbmsInfo->connection, "SET AUTOCOMMIT = 0" );
		mysql_query( dbmsInfo->connection, "BEGIN" );
		}

	/* Submit the query to the MySQL server */
	convertQuery( query, command );
	if( boundDate != 0 )
		{
		status = bindDate( query, boundDate );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = mysql_query( dbmsInfo->connection, query );
	if( updateType == DBMS_UPDATE_COMMIT )
		{
		status = mysql_query( dbmsInfo->connection,
							  cryptStatusOK( status ) ? \
							  "COMMIT" : "ROLLBACK" );
		mysql_query( dbmsInfo->connection, "SET AUTOCOMMIT = 1" );
		}
	if( status == -1 )
		return( getErrorInfo( dbmsInfo, CRYPT_ERROR_WRITE ) );

	/* If we're performing a delete, the operation will succeed even though
	   nothing was found to delete so we make sure we actually changed
	   something */
	if( !strnicmp( query, "DELETE", 6 ) && \
		mysql_affected_rows( dbmsInfo->connection ) <= 0 )
		return( CRYPT_ERROR_NOTFOUND );

	return( CRYPT_OK );
	}

/* Perform a transaction which returns information */

static int performQuery( DBMS_STATE_INFO *dbmsInfo, const char *command,
						 char *data, int *dataLength, time_t boundDate,
						 const DBMS_QUERY_TYPE queryType )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int status = CRYPT_OK;

	/* If we're cancelling an ongoing query, discard the result set
	   (unfortunately we have to actually read it rather than just
	   dropping it, see the comment further down for the reason), and
	   restore the single-result fetch limit */
	if( queryType == DBMS_QUERY_CANCEL )
		{
		if( dbmsInfo->result != NULL )
			{
			mysql_free_result( dbmsInfo->result );
			dbmsInfo->result = NULL;
			}
		mysql_query( dbmsInfo->connection, "SET SQL_SELECT_LIMIT=1" );
		return( CRYPT_OK );
		}

	/* If we're starting an ongoing query, remove the fetch limit to allow
	   more than one result to be returned */
	if( queryType == DBMS_QUERY_START )
		{
		mysql_query( dbmsInfo->connection, "SET SQL_SELECT_LIMIT=0" );
		dbmsInfo->result = NULL;
		}

	/* Submit the query to the MySQL server.  Unfortunately we have to call
	   mysql_store_result() even if we don't need the result or it'll remain
	   in the server's buffer and be returned on the next fetch, however
	   since the fetch limit is set to one row this isn't much of a problem */
	if( queryType == DBMS_QUERY_START || queryType == DBMS_QUERY_CHECK || \
		queryType == DBMS_QUERY_NORMAL )
		{
		convertQuery( query, command );
		if( boundDate != 0 )
			{
			status = bindDate( query, boundDate );
			if( cryptStatusError( status ) )
				return( status );
			}
		if( mysql_query( dbmsInfo->connection, query ) == -1 )
			return( getErrorInfo( dbmsInfo, CRYPT_ERROR_READ ) );

		/* See what we got */
		dbmsInfo->result = mysql_store_result( dbmsInfo->connection );
		if( dbmsInfo->result == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		}

	/* If we're only doing a check, we're done */
	if( queryType == DBMS_QUERY_CHECK )
		{
		if( mysql_num_rows( dbmsInfo->result ) <= 0 )
			status = CRYPT_ERROR_NOTFOUND;
		mysql_free_result( dbmsInfo->result );
		dbmsInfo->result = NULL;
		return( status );
		}

	/* Fetch the next returned row (this is always just a single value, the
	   key data) */
	if( queryType == DBMS_QUERY_START || queryType == DBMS_QUERY_CONTINUE || \
		queryType == DBMS_QUERY_NORMAL )
		{
		MYSQL_ROW row;

		row = mysql_fetch_row( dbmsInfo->result );
		if( row == NULL )
			status = CRYPT_ERROR_NOTFOUND;
		else
			{
			*dataLength = strlen( row[ 0 ] );
			if( *dataLength >= MAX_QUERY_RESULT_SIZE )
				{
				/* Too much data returned */
				*dataLength = 0;
				status = CRYPT_ERROR_OVERFLOW;
				}
			else
				strcpy( data, row[ 0 ] );
			}
		}

	/* If it's a one-off query, free the result set */
	if( queryType == DBMS_QUERY_NORMAL )
		{
		mysql_free_result( dbmsInfo->result );
		dbmsInfo->result = NULL;
		}

	return( status );
	}

/* Fetch extended error information from the database state info */

static void performErrorQuery( DBMS_STATE_INFO *dbmsInfo, int *errorCode,
							   char *errorMessage )
	{
	*errorCode = dbmsInfo->errorCode;
	strcpy( errorMessage, dbmsInfo->errorMessage );
	}

/* Pull in the shared database RPC routines, renaming the generic dispatch
   function to the MySQL-specific one which is called directly by the
   marshalling code */

#define processCommand( stateInfo, buffer ) \
		mysqlProcessCommand( stateInfo, buffer )

#include "dbx_rpc.c"

#endif /* USE_MYSQL */
