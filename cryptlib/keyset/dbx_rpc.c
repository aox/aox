/****************************************************************************
*																			*
*						 cryptlib Database RPC Interface					*
*						Copyright Peter Gutmann 1997-2002					*
*																			*
****************************************************************************/

/* This file isn't a standalone module but is meant to be #included into
   whichever of the dbxXXXX.c database client files it's used with */

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "rpc.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
  #include "../misc/rpc.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "misc/rpc.h"
#endif /* Compiler-specific includes */

/* Handlers for the various commands */

static int cmdClose( void *stateInfo, COMMAND_INFO *cmd )
	{
	assert( cmd->type == DBX_COMMAND_CLOSE );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 0 );
	assert( cmd->noStrArgs == 0 );

	closeDatabase( stateInfo );
	return( CRYPT_OK );
	}

static int cmdGetErrorInfo( void *stateInfo, COMMAND_INFO *cmd )
	{
	assert( cmd->type == DBX_COMMAND_GETERRORINFO );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 0 );
	assert( cmd->noStrArgs == 1 );

	performErrorQuery( stateInfo, &cmd->arg[ 0 ], cmd->strArg[ 0 ] );
	cmd->strArgLen[ 0 ] = strlen( cmd->strArg[ 0 ] );
	return( CRYPT_OK );
	}

static int cmdOpen( void *stateInfo, COMMAND_INFO *cmd )
	{
	int hasBinaryBlobs, status;

	assert( cmd->type == DBX_COMMAND_OPEN );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 1 );
	assert( cmd->arg[ 0 ] >= CRYPT_KEYOPT_NONE && \
			cmd->arg[ 0 ] < CRYPT_KEYOPT_LAST );
	assert( cmd->noStrArgs == 1 );

	status = openDatabase( stateInfo, cmd->strArg[ 0 ], cmd->arg[ 0 ],
						   &hasBinaryBlobs );
	if( cryptStatusOK( status ) )
		cmd->arg[ 0 ] = hasBinaryBlobs;
	return( status );
	}

static int cmdQuery( void *stateInfo, COMMAND_INFO *cmd )
	{
	const void *dataPtr = cmd->strArg[ 1 ];
	const int argIndex = cmd->noStrArgs - 1;
	time_t timeValue = 0;
	int dataLength, status;

	assert( cmd->type == DBX_COMMAND_QUERY );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 1 );
	assert( cmd->arg[ 0 ] >= DBMS_QUERY_NORMAL && \
			cmd->arg[ 0 ] <= DBMS_QUERY_CANCEL );
	assert( cmd->noStrArgs >= 1 && cmd->noStrArgs <= 3 );

	/* If one of the string args is a bound date, convert it into a time_t */
	if( cmd->noStrArgs >= 2 && cmd->strArgLen[ 1 ] == 8 )
		{
		const BYTE *timeValuePtr = cmd->strArg[ 1 ];

		/* Extract the time_t from the 64-bit time value */
#ifdef _BIG_WORDS
		timeValue = ( time_t ) timeValuePtr[ 3 ] << 32 | \
					( time_t ) timeValuePtr[ 4 ] << 24 | \
					( time_t ) timeValuePtr[ 5 ] << 16 | \
					( time_t ) timeValuePtr[ 6 ] << 8 | \
					( time_t ) timeValuePtr[ 7 ];
#else
		timeValue = ( time_t ) timeValuePtr[ 4 ] << 24 | \
					( time_t ) timeValuePtr[ 5 ] << 16 | \
					( time_t ) timeValuePtr[ 6 ] << 8 | \
					( time_t ) timeValuePtr[ 7 ];
#endif /* _BIG_WORDS */
		}

	status = performQuery( stateInfo, cmd->strArg[ 0 ],
						   cmd->strArg[ argIndex ], &dataLength, timeValue,
						   cmd->arg[ 0 ] );
	if( cryptStatusOK( status ) )
		cmd->strArgLen[ argIndex ] = \
								( cmd->arg[ 0 ] == DBMS_QUERY_NORMAL || \
								  cmd->arg[ 0 ] == DBMS_QUERY_CONTINUE ) ? \
								dataLength : 0;
	return( status );
	}

static int cmdUpdate( void *stateInfo, COMMAND_INFO *cmd )
	{
	const void *dataPtr = cmd->strArg[ 1 ];
	int dataLength = cmd->strArgLen[ 1 ];
	time_t timeValue = 0;

	assert( cmd->type == DBX_COMMAND_UPDATE );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 1 );
	assert( cmd->noStrArgs >= 0 && cmd->noStrArgs <= 3 );

	/* If one of the string args is a bound date, convert it into a time_t */
	if( cmd->noStrArgs >= 2 && cmd->strArgLen[ 1 ] == 8 )
		{
		const BYTE *timeValuePtr = cmd->strArg[ 1 ];

		/* Extract the time_t from the 64-bit time value */
#ifdef _BIG_WORDS
		timeValue = ( time_t ) timeValuePtr[ 3 ] << 32 | \
					( time_t ) timeValuePtr[ 4 ] << 24 | \
					( time_t ) timeValuePtr[ 5 ] << 16 | \
					( time_t ) timeValuePtr[ 6 ] << 8 | \
					( time_t ) timeValuePtr[ 7 ];
#else
		timeValue = ( time_t ) timeValuePtr[ 4 ] << 24 | \
					( time_t ) timeValuePtr[ 5 ] << 16 | \
					( time_t ) timeValuePtr[ 6 ] << 8 | \
					( time_t ) timeValuePtr[ 7 ];
#endif /* _BIG_WORDS */

		/* Since the first arg is the date, the data will be in the second
		   arg */
		dataPtr = cmd->strArg[ 2 ];
		dataLength = cmd->strArgLen[ 2 ];
		}

	return( performUpdate( stateInfo, cmd->strArg[ 0 ],
						   dataLength ? dataPtr : NULL, dataLength,
						   timeValue, cmd->arg[ 0 ] ) );
	}

/* Process a command from the client and send it to the appropriate handler */

static const COMMAND_HANDLER commandHandlers[] = {
	NULL, NULL, cmdOpen, cmdClose, cmdQuery, cmdUpdate, cmdGetErrorInfo };

void processCommand( void *stateInfo, BYTE *buffer )
	{
	COMMAND_INFO cmd = { 0 };
	BYTE header[ COMMAND_FIXED_DATA_SIZE ], *bufPtr;
	long totalLength;
	int i, status;

	/* Read the client's message header */
	memcpy( header, buffer, COMMAND_FIXED_DATA_SIZE );

	/* Process the fixed message header and make sure it's valid */
	getMessageType( header, cmd.type, cmd.flags, cmd.noArgs, cmd.noStrArgs );
	totalLength = getMessageLength( header + COMMAND_WORDSIZE );
	if( !dbxCheckCommandInfo( &cmd, totalLength ) || \
		cmd.type == COMMAND_RESULT )
		{
		assert( NOTREACHED );

		/* Return an invalid result message */
		putMessageType( buffer, COMMAND_RESULT, 0, 0, 0 );
		putMessageLength( buffer + COMMAND_WORDSIZE, 0 );
		return;
		}

	/* Read the rest of the clients message */
	bufPtr = buffer + COMMAND_FIXED_DATA_SIZE;
	for( i = 0; i < cmd.noArgs; i++ )
		{
		cmd.arg[ i ] = getMessageWord( bufPtr );
		bufPtr += COMMAND_WORDSIZE;
		}
	for( i = 0; i < cmd.noStrArgs; i++ )
		{
		cmd.strArgLen[ i ] = getMessageWord( bufPtr );
		cmd.strArg[ i ] = bufPtr + COMMAND_WORDSIZE;
		bufPtr += COMMAND_WORDSIZE + cmd.strArgLen[ i ];
		}
	if( !dbxCheckCommandConsistency( &cmd, totalLength ) )
		{
		assert( NOTREACHED );

		/* Return an invalid result message */
		putMessageType( buffer, COMMAND_RESULT, 0, 0, 0 );
		putMessageLength( buffer + COMMAND_WORDSIZE, 0 );
		return;
		}

	/* If it's a command which returns a string value, obtain the returned
	   data in the buffer.  Normally we limit the size to the maximum
	   attribute size, however encoded objects and data popped from
	   envelopes/sessions can be larger than this so we use the entire buffer
	   minus a safety margin */
	if( cmd.type == DBX_COMMAND_QUERY || \
		cmd.type == DBX_COMMAND_GETERRORINFO )
		{
		cmd.strArg[ cmd.noStrArgs ] = bufPtr;
		cmd.strArgLen[ cmd.noStrArgs ] = ( cmd.type == DBX_COMMAND_QUERY ) ? \
										 MAX_ENCODED_CERT_SIZE : MAX_ERRMSG_SIZE;
		cmd.noStrArgs++;
		}

	/* Null-terminate the first string arg if there's one present, either the
	   database name or the SQL command.  If there's something following it
	   in the buffer this is redundant (but safe) because it'll already be
	   followed by the MSB of the next string arg's length, if there's
	   nothing following it it's safe as well */
	if( cmd.type == DBX_COMMAND_OPEN || \
		( cmd.type == DBX_COMMAND_UPDATE && \
		  cmd.arg[ 0 ] != DBMS_UPDATE_ABORT ) || \
		( cmd.type == DBX_COMMAND_QUERY && \
		  ( cmd.arg[ 0 ] == DBMS_QUERY_NORMAL || \
		    cmd.arg[ 0 ] == DBMS_QUERY_CHECK || \
			cmd.arg[ 0 ] == DBMS_QUERY_START ) ) )
		( ( char * ) cmd.strArg[ 0 ] )[ cmd.strArgLen[ 0 ] ] = '\0';

	/* Process the command and copy any return information back to the
	   caller */
	status = commandHandlers[ cmd.type ]( stateInfo, &cmd );
	bufPtr = buffer;
	if( cryptStatusError( status ) )
		{
		/* The command failed, return a simple status value */
		putMessageType( bufPtr, COMMAND_RESULT, 0, 1, 0 );
		putMessageLength( bufPtr + COMMAND_WORDSIZE, COMMAND_WORDSIZE );
		putMessageWord( bufPtr + COMMAND_WORD1_OFFSET, status );
		return;
		}
	if( cmd.type == DBX_COMMAND_OPEN )
		{
		/* Return numeric value */
		putMessageType( bufPtr, COMMAND_RESULT, 0, 2, 0 );
		putMessageLength( bufPtr + COMMAND_WORDSIZE, COMMAND_WORDSIZE * 2 );
		putMessageWord( bufPtr + COMMAND_WORD1_OFFSET, CRYPT_OK );
		putMessageWord( bufPtr + COMMAND_WORD2_OFFSET, cmd.arg[ 0 ] );
		return;
		}
	if( cmd.type == DBX_COMMAND_QUERY )
		{
		const int argIndex = cmd.noStrArgs - 1;
		const long dataLength = cmd.strArgLen[ argIndex ];

		/* Return data and length.  In some cases (during ongoing queries
		   with no submitted SQL data) we can be called without any incoming
		   args, there's no space at the start of the shared input/output
		   buffer so we have to move the returned string back in the buffer
		   to avoid overwriting it with the other information we're about to
		   return */
		if( dataLength )
			memmove( bufPtr + COMMAND_WORD3_OFFSET,
					 cmd.strArg[ argIndex ], dataLength );
		putMessageType( bufPtr, COMMAND_RESULT, 0, 1, 1 );
		putMessageLength( bufPtr + COMMAND_WORDSIZE,
						  ( COMMAND_WORDSIZE * 2 ) + cmd.strArgLen[ argIndex ] );
		putMessageWord( bufPtr + COMMAND_WORD1_OFFSET, CRYPT_OK );
		putMessageWord( bufPtr + COMMAND_WORD2_OFFSET, dataLength );
		return;
		}
	if( cmd.type == DBX_COMMAND_GETERRORINFO )
		{
		const long dataLength = cmd.strArgLen[ 0 ];

		/* Return data and length.  Because we were called without any
		   incoming args, there's no space at the start of the shared input/
		   output buffer so we have to move the returned string back in the
		   buffer to avoid overwriting it with the other information we're
		   about to return */
		if( dataLength )
			memmove( bufPtr + COMMAND_WORD4_OFFSET, cmd.strArg[ 0 ],
					 dataLength );
		putMessageType( bufPtr, COMMAND_RESULT, 0, 2, 1 );
		putMessageLength( bufPtr + COMMAND_WORDSIZE,
						  ( COMMAND_WORDSIZE * 2 ) + cmd.strArgLen[ 0 ] );
		putMessageWord( bufPtr + COMMAND_WORD1_OFFSET, CRYPT_OK );
		putMessageWord( bufPtr + COMMAND_WORD2_OFFSET, cmd.arg[ 0 ] );
		putMessageWord( bufPtr + COMMAND_WORD3_OFFSET, dataLength );
		return;
		}
	putMessageType( bufPtr, COMMAND_RESULT, 0, 1, 0 );
	putMessageLength( bufPtr + COMMAND_WORDSIZE, COMMAND_WORDSIZE );
	putMessageWord( bufPtr + COMMAND_WORD1_OFFSET, CRYPT_OK );
	}
