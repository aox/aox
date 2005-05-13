/****************************************************************************
*																			*
*						MVS Randomness-Gathering Code						*
*					  Copyright Peter Gutmann 1999-2003						*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see random.c */

/* General includes */

#include <stdlib.h>
#include <string.h>
#include <sys/times.h>
#include <sys/resource.h>
#include "crypt.h"

/* Define the MVS assembler module used to gather random data */

#pragma linkage( MVSENT, OS )
#pragma map( readRandom, "MVSENT" )
int readRandom( int length, unsigned char *buffer );

/* The size of the intermediate buffer used to accumulate polled data */

#define RANDOM_BUFSIZE	4096

/* Slow and fast polling routines.  Since we require MVS system access
   to get anything useful, the fast poll is really just a subset of the
   slow poll, although it's kept distinct in case there's a need to add
   poll-specific facilities at a later date */

void fastPoll( void )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ RANDOM_BUFSIZE ];
	int quality = 10, status;

	/* For the sake of speed we only get 256 bytes for the fast poll */
	status = readRandom( 256, buffer );
	assert( status == 0 );
	setMessageData( &msgData, buffer, 256 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE_S, &msgData,
					 CRYPT_IATTRIBUTE_ENTROPY );
	zeroise( buffer, sizeof( buffer ) );
	if( status == 0 )
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE,
						 &quality, CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
	}

void slowPoll( void )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ RANDOM_BUFSIZE ];
	int quality = 90, status;

	status = readRandom( RANDOM_BUFSIZE, buffer );
	assert( status == 0 );
	setMessageData( &msgData, buffer, RANDOM_BUFSIZE );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE_S, &msgData,
					 CRYPT_IATTRIBUTE_ENTROPY );
	zeroise( buffer, sizeof( buffer ) );
	if( status == 0 )
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE,
						 &quality, CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
	}
