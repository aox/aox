/****************************************************************************
*																			*
*						   ASN.1 Checking Routines							*
*						Copyright Peter Gutmann 1992-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "bn.h"
  #include "asn1.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../bn/bn.h"
  #include "asn1.h"
#else
  #include "crypt.h"
  #include "bn/bn.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* The maximum nesting level for constructed or encapsulated objects (this
   can get surprisingly high for some of the more complex attributes).  This
   value is chosen to pass all normal certs while avoiding stack overflows
   for artificial bad data */

#define MAX_NESTING_LEVEL	50

/* When we parse a nested data object encapsulated within a larger object,
   the length is initially set to a magic value which is adjusted to the
   actual length once we start parsing the object */

#define LENGTH_MAGIC		177545L

/* Current parse state.  This is used to check for potential BIT STRING and
   OCTET STRING targets for OCTET/BIT STRING holes, which are always
   preceded by an AlgorithmIdentifier.  In order to detect these without
   having to know every imaginable AlgorithmIdentifier OID, we check for the
   following sequence of events:

	SEQUENCE {			-- STATE_SEQUENCE
		OID,			-- STATE_HOLE_OID
		NULL			-- STATE_NULL
		},
	BIT STRING			-- STATE_HOLE_BITSTRING

	SEQUENCE {			-- STATE_SEQUENCE
		OID,			-- STATE_HOLE_OID
		BOOLEAN OPT,	-- STATE_BOOLEAN (following a STATE_HOLE_OID)
		OCTET STRING	-- STATE_HOLE_OCTETSTRING

   Once we reach any of the STATE_HOLE_* states, if we hit a BIT STRING or
   OCTET STRING we try and locate encapsulated content within it.  This type 
   of checking is rather awkward in the (otherwise stateless) code, but is 
   the only way to be sure that it's safe to try burrowing into an OCTET 
   STRING or BIT STRING to try to find encapsulated data, since otherwise 
   even with relatively strict checking there's still a very small chance 
   that random data will look like a nested object */

typedef enum {
	/* Generic non-state */
	STATE_NONE,

	/* States corresponding to ASN.1 primitives */
	STATE_BOOLEAN, STATE_NULL, STATE_OID, STATE_SEQUENCE,

	/* States corresponding to different parts of a SEQUENCE { OID, optional,
	   OCTET/BIT STRING } sequence */
	STATE_HOLE_OID, STATE_HOLE_BITSTRING, STATE_HOLE_OCTETSTRING,

	/* Error state */
	STATE_ERROR
	} ASN1_STATE;

/* Structure to hold info on an ASN.1 item */

typedef struct {
	int tag;			/* Tag */
	long length;		/* Data length */
	BOOLEAN indefinite;	/* Item has indefinite length */
	int headerSize;		/* Size of tag+length */
	} ASN1_ITEM;

/* Get an ASN.1 object's tag and length */

static int getItem( STREAM *stream, ASN1_ITEM *item )
	{
	const long offset = stell( stream );
	long length;
	int status;

	memset( item, 0, sizeof( ASN1_ITEM ) );
	item->tag = peekTag( stream );
	if( checkEOC( stream ) )
		{
		item->headerSize = 2;
		return( sStatusOK( stream ) ? STATE_NONE : STATE_ERROR );
		}
	status = readLongGenericHole( stream, &length, item->tag );
	if( cryptStatusError( status ) )
		return( STATE_ERROR );
	item->headerSize = stell( stream ) - offset;
	if( length == CRYPT_UNUSED )
		item->indefinite = TRUE;
	else
		item->length = length;
	return( STATE_NONE );
	}

/* Check whether an ASN.1 object is encapsulated inside an OCTET STRING or
   BIT STRING.  After performing the various checks we have to explicitly
   clear the stream error state since the probing for valid data could have
   set the error indicator if nothing valid was found */

static BOOLEAN checkEncapsulation( STREAM *stream, const int length,
								   const BOOLEAN isBitstring,
								   const ASN1_STATE state )
	{
	BOOLEAN isEncapsulated = TRUE;
	long streamPos = stell( stream );
	int tag = peekTag( stream ), innerLength, status;

	/* Make sure that there's an encapsulated object present.  This is a
	   reasonably effective check, but unfortunately its effectiveness
	   means that it'll reject nested objects with incorrect lengths.  It's
	   not really possible to fix this, either there'll be false positives
	   due to true OCTET/BIT STRINGs that look like they might contain
	   nested data, or there'll be no false positives but nested content
	   with slightly incorrect encodings will be missed */
	status = readGenericHole( stream, &innerLength, DEFAULT_TAG );
	if( cryptStatusError( status ) || \
		( stell( stream ) - streamPos ) + innerLength != length )
		{
		sClearError( stream );
		sseek( stream, streamPos );
		return( FALSE );
		}

	/* A BIT STRING that encapsulates something only ever contains
	   { SEQUENCE { INTEGER, ... } } */
	if( isBitstring )
		{
		/* Make sure that there's a SEQUENCE containing an INTEGER present */
		if( tag != BER_SEQUENCE || peekTag( stream ) != BER_INTEGER || \
			cryptStatusError( readGenericHole( stream, &innerLength, 
											   BER_INTEGER ) ) || \
			innerLength > length - 4 )
			isEncapsulated = FALSE;

		sClearError( stream );
		sseek( stream, streamPos );
		return( isEncapsulated );
		}

	/* An OCTET STRING is more complex.  This could encapsulate any of:

		BIT STRING: keyUsage, crlReason, Netscape certType, must be
			<= 16 bits and a valid bitstring.
		GeneralisedTime: invalidityDate: Not possible to check directly
			since the obvious check for a valid length will also fail
			invalid-length encodings, missing the very thing we usually
			want to check for, so all we can check for is a vaguely valid
			length.
		IA5String: Netscape extensions, the most that we can do is perform 
			an approximate length range check
		INTEGER: deltaCRLIndicator, crlNumber, must be <= 16 bits.
		OCTET STRING: keyID, again the most we can do is perform an
			approximate length range check.
		OID: holdInstructionCode, again just an approximate length range 
			check.
		SEQUENCE: most extensions, a bit difficult to check but again we can 
			make sure that the length is right for strict encapsulation */
	switch( tag )
		{
		case BER_BITSTRING:
			if( innerLength < 0 || innerLength > 2 )
				isEncapsulated = FALSE;
			else
				{
				int ch = sgetc( stream );

				if( ch < 0 || ch > 7 )
					isEncapsulated = FALSE;
				}
			break;

		case BER_TIME_GENERALIZED:
			if( innerLength < 10 || innerLength > 20 )
				isEncapsulated = FALSE;
			break;

		case BER_INTEGER:
			if( innerLength < 0 || innerLength > 2 )
				isEncapsulated = FALSE;
			break;

		case BER_STRING_IA5:
		case BER_OCTETSTRING:
			if( innerLength < 2 || innerLength > 256 )
				isEncapsulated = FALSE;
			break;

		case BER_OBJECT_IDENTIFIER:
			if( innerLength < 3 || innerLength > MAX_OID_SIZE )
				isEncapsulated = FALSE;
			break;

		case BER_SEQUENCE:
			break;

		default:
			isEncapsulated = FALSE;
		}
	sClearError( stream );
	sseek( stream, streamPos );
	return( isEncapsulated );
	}

/* Check a primitive ASN.1 object */

static ASN1_STATE checkASN1( STREAM *stream, long length,
							 const int isIndefinite, const int level,
							 ASN1_STATE state, 
							 const BOOLEAN checkDataElements );

static ASN1_STATE checkPrimitive( STREAM *stream, const ASN1_ITEM *item,
								  const int level, const ASN1_STATE state )
	{
	int length = ( int ) item->length, ch, i;

	assert( state >= STATE_NONE && state <= STATE_ERROR );

	/* Perform a sanity check of input data */
	if( level >= MAX_NESTING_LEVEL || state == STATE_ERROR || \
		item->length < 0 )
		return( STATE_ERROR );

	/* In theory only NULL and EOC elements (BER_RESERVED) are allowed to 
	   have a zero length, but some broken implementations (Netscape, Van 
	   Dyke) encode numeric zero values as a zero-length element so we have 
	   to accept these as well */
	if( item->length <= 0 && item->tag != BER_NULL && \
							 item->tag != BER_RESERVED && \
							 item->tag != BER_INTEGER )
		return( STATE_ERROR );

	/* Perform a general check that everything is OK.  We don't check for 
	   invalid content except where it would impede decoding of the data in
	   order to avoid failing on all of the broken certs out there */
	switch( item->tag )
		{
		case BER_BOOLEAN:
			return( cryptStatusError( sgetc( stream ) ) ? \
					STATE_ERROR : STATE_BOOLEAN );

		case BER_INTEGER:
		case BER_ENUMERATED:
			if( length > 0 &&	/* May be encoded as a zero-length value */
				cryptStatusError( sSkip( stream, length ) ) )
				return( STATE_ERROR );
			return( STATE_NONE );

		case BER_BITSTRING:
			/* Check the number of unused bits */
			ch = sgetc( stream );
			length--;
			if( length < 0 || ch < 0 || ch > 7 )
				/* Invalid number of unused bits */
				return( STATE_ERROR );

			/* If it's short enough to be a bit flag, it's just a sequence 
			   of bits */
			if( length <= 4 )
				{
				if( length > 0 && \
					cryptStatusError( sSkip( stream, length ) ) )
					return( STATE_ERROR );
				return( STATE_NONE );
				}
			/* Fall through */

		case BER_OCTETSTRING:
			{
			const BOOLEAN isBitstring = item->tag == BER_BITSTRING;

			/* Check to see whether an OCTET STRING or BIT STRING hole is 
			   allowed at this point (a BIT STRING must be preceded by 
			   { SEQ, OID, NULL }, an OCTET STRING must be preceded by 
			   { SEQ, OID, {BOOLEAN} }), and if it's something encapsulated 
			   inside the string, handle it as a constructed item */
			if( ( ( isBitstring && state == STATE_HOLE_BITSTRING ) || \
				  ( !isBitstring && ( state == STATE_HOLE_OID || \
									  state == STATE_HOLE_OCTETSTRING ) ) ) && \
				checkEncapsulation( stream, length, isBitstring, state ) )
				{
				ASN1_STATE encapsState;

				encapsState = checkASN1( stream, length, item->indefinite,
										 level + 1, STATE_NONE, TRUE );
				return( ( encapsState == STATE_ERROR ) ? \
						STATE_ERROR : STATE_NONE );
				}

			/* Skip the data */
			return( cryptStatusError( sSkip( stream, length ) ) ? \
					STATE_ERROR : STATE_NONE );
			}

		case BER_OBJECT_IDENTIFIER:
			if( length > MAX_OID_SIZE - 2 )
				/* Total OID size (including tag and length, since they're 
				   treated as a blob) should be less than a sane limit */
				return( STATE_ERROR );
			return( cryptStatusError( sSkip( stream, length ) ) ? \
					STATE_ERROR : STATE_OID );

		case BER_RESERVED:
			break;					/* EOC */

		case BER_NULL:
			return( STATE_NULL );

		case BER_STRING_BMP:
		case BER_STRING_GENERAL:	/* Produced by Entrust software */
		case BER_STRING_IA5:
		case BER_STRING_ISO646:
		case BER_STRING_NUMERIC:
		case BER_STRING_PRINTABLE:
		case BER_STRING_T61:
		case BER_STRING_UTF8:
			return( cryptStatusError( sSkip( stream, length ) ) ? \
					STATE_ERROR : STATE_NONE );

		case BER_TIME_UTC:
		case BER_TIME_GENERALIZED:
			if( item->tag == BER_TIME_GENERALIZED )
				{
				if( length != 15 )
					return( STATE_ERROR );
				}
			else
				if( length != 11 && length != 13 )
					return( STATE_ERROR );
			for( i = 0; i < length - 1; i++ )
				{
				ch = sgetc( stream );
				if( ch < '0' || ch > '9' )
					return( STATE_ERROR );
				}
			if( sgetc( stream ) != 'Z' )
				return( STATE_ERROR );
			return( STATE_NONE );

		default:
			/* Disallowed or unrecognised primitive */
			return( STATE_ERROR );
		}

	return( STATE_NONE );
	}

/* Check a single ASN.1 object.  checkASN1() and checkASN1Object() are 
   mutually recursive, the ...Object() version only exists to avoid a
   large if... else chain in checkASN1().  A typical checking run is
   as follows:

	30 nn			cASN1 -> cAObj -> cASN1
	   30 nn						  cASN1 -> cAObj -> cASN1
		  04 nn nn										cASN1 -> cPrim

	30 80			cASN1 -> cAObj -> cASN1
	   30 80						  cASN1 -> cAObj -> cASN1
		  04 nn nn										cASN1 -> cPrim
	   00 00						  cASN1 <- cAObj <- cASN1
	00 00			cASN1 <- cAObj <- cASN1

   The use of checkASN1Object() leads to an (apparently) excessively deep 
   call hierarchy, but that's mostly an artifact of the way that it's 
   diagrammed here */

static ASN1_STATE checkASN1Object( STREAM *stream, const ASN1_ITEM *item,
								   const int level, const ASN1_STATE state,
								   const BOOLEAN checkDataElements )
	{
	ASN1_STATE newState;

	assert( state >= STATE_NONE && state <= STATE_ERROR );

	/* Perform a sanity check of input data */
	if( level >= MAX_NESTING_LEVEL || state == STATE_ERROR || \
		item->length < 0 )
		return( STATE_ERROR );

	/* If we're checking data elements, check the contents for validity */
	if( checkDataElements && ( item->tag & BER_CLASS_MASK ) == BER_UNIVERSAL )
		{
		/* If it's constructed, parse the nested object(s) */
		if( ( item->tag & BER_CONSTRUCTED_MASK ) == BER_CONSTRUCTED )
			{
			/* Special-case for zero-length SEQUENCE/SET */
			if( item->length <= 0 && !item->indefinite )
				return( STATE_NONE );

			return( checkASN1( stream, item->length, item->indefinite,
							   level + 1, ( item->tag == BER_SEQUENCE ) ? \
									STATE_SEQUENCE : STATE_NONE, TRUE ) );
			}

		/* It's primitive, check the primitive element with optional state
		   update: SEQ + OID -> HOLE_OID; OID + { NULL | BOOLEAN } -> 
		   HOLE_BITSTRING/HOLE_OCTETSTRING */
		newState = checkPrimitive( stream, item, level + 1, state );
		if( state == STATE_SEQUENCE && newState == STATE_OID )
			return( STATE_HOLE_OID );
		if( state == STATE_HOLE_OID )
			{
			if( newState == STATE_NULL )
				return( STATE_HOLE_BITSTRING );
			if( newState == STATE_BOOLEAN )
				return( STATE_HOLE_OCTETSTRING );
			}
		return( ( newState == STATE_ERROR ) ? STATE_ERROR : STATE_NONE );
		}

	/* Zero-length objects are usually an error, however PKCS #10 has an
	   attribute-encoding ambiguity that produces zero-length tagged 
	   extensions and OCSP has its braindamaged context-specific tagged 
	   NULLs so we don't complain about them if they have context-specific 
	   tags */
	if( item->length <= 0 && !item->indefinite )
		return( ( ( item->tag & BER_CLASS_MASK ) == BER_CONTEXT_SPECIFIC ) ? \
				STATE_NONE : STATE_ERROR );

	assert( item->length > 0 || item->indefinite );

	/* If it's constructed, parse the nested object(s) */
	if( ( item->tag & BER_CONSTRUCTED_MASK ) == BER_CONSTRUCTED )
		{
		newState = checkASN1( stream, item->length, item->indefinite,
							  level + 1, STATE_NONE, checkDataElements );
		return( ( newState == STATE_ERROR ) ? \
				STATE_ERROR : STATE_NONE );
		}

	/* It's a context-specific tagged item that could contain anything, just 
	   skip it */
	if( ( item->tag & BER_CLASS_MASK ) != BER_CONTEXT_SPECIFIC || \
		item->length <= 0 || \
		cryptStatusError( sSkip( stream, item->length ) ) )
		return( STATE_ERROR );
	return( STATE_NONE );
	}

/* Check a complex ASN.1 object */

static ASN1_STATE checkASN1( STREAM *stream, long length, const int isIndefinite,
							 const int level, ASN1_STATE state,
							 const BOOLEAN checkDataElements )
	{
	ASN1_ITEM item;
	long lastPos = stell( stream );
	ASN1_STATE status;

	assert( state >= STATE_NONE && state <= STATE_ERROR );
	assert( level > 0 || length == LENGTH_MAGIC );
	assert( ( isIndefinite && length == 0 ) || \
			( !isIndefinite && length >= 0 ) );

	/* Perform a sanity check of input data */
	if( level >= MAX_NESTING_LEVEL || state == STATE_ERROR || length < 0 )
		return( STATE_ERROR );

	while( ( status = getItem( stream, &item ) ) == STATE_NONE )
		{
		/* If this is the top level (for which the level isn't known in
		   advance) and the item has a definite length, set the length to 
		   the item's length */
		if( level == 0 && !item.indefinite )
			length = item.headerSize + item.length;

		/* If this is an EOC (tag == BER_RESERVED) for an indefinite item, 
		   we're done */
		if( isIndefinite && item.tag == BER_RESERVED )
			return( STATE_NONE );

		/* Check the object */
		if( !checkDataElements && item.length > 0 )
			{
			/* Shortcut to save a level of recursion, if we're not 
			   interested in the data elements and the item has a definite 
			   length, just skip over it and continue */
			if( cryptStatusError( sSkip( stream, item.length ) ) )
				state = STATE_ERROR;
			}
		else
			state = checkASN1Object( stream, &item, level + 1, state, 
									 checkDataElements );
		if( state == STATE_ERROR || sGetStatus( stream ) != CRYPT_OK )
			return( STATE_ERROR );

		/* If it's an indefinite-length object, we have to keep going until 
		   we find the EOC octets */
		if( isIndefinite )
			continue;

		/* If the outermost object was of indefinite length and we've come 
		   back to the top level, exit.  The isIndefinite flag won't be set
		   at this point because we can't know the length status before we
		   start, but it's implicitly indicated by finding a length of
		   LENGTH_MAGIC at the topmost level */
		if( level == 0 && length == LENGTH_MAGIC )
			return( STATE_NONE );

		/* Check whether we've reached the end of the current (definite-
		   length) object */
		length -= stell( stream ) - lastPos;
		lastPos = stell( stream );
		if( length <= 0 )
			return( ( length < 0 ) ? STATE_ERROR : state );
		}

	return( ( status == STATE_NONE ) ? STATE_NONE : STATE_ERROR );
	}

/* Check the encoding of a complete object and determine its length */

int checkObjectEncoding( const void *objectPtr, const int objectLength )
	{
	STREAM stream;
	ASN1_STATE state;
	int length;

	assert( isReadPtr( objectPtr, objectLength ) );
	assert( objectLength > 0 );

	sMemConnect( &stream, objectPtr, objectLength );
	state = checkASN1( &stream, LENGTH_MAGIC, FALSE, 0, STATE_NONE, TRUE );
	length = stell( &stream );
	sMemDisconnect( &stream );
	return( ( state == STATE_ERROR ) ? CRYPT_ERROR_BADDATA : length );
	}

/* Recursively dig into an ASN.1 object as far as we need to to determine 
   its length */

static long findObjectLength( STREAM *stream, const BOOLEAN isLongObject )
	{
	const long startPos = stell( stream );
	long length;
	int shortLength, status;

	/* Try for a definite length */
	if( isLongObject )
		status = readLongGenericHole( stream, &length, DEFAULT_TAG );
	else
		status = readGenericHoleI( stream, &shortLength, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	if( !isLongObject )
		length = shortLength;

	/* If it's an indefinite-length object, burrow down into it to find its 
	   actual length */
	if( length == CRYPT_UNUSED )
		{
		sseek( stream, startPos );
		length = checkASN1( stream, LENGTH_MAGIC, FALSE, 0, STATE_NONE, FALSE );
		if( length == STATE_ERROR )
			return( CRYPT_ERROR_BADDATA );
		length = stell( stream ) - startPos;
		}
	else
		/* It's a definite-length object, add the size of the tag+length */
		length += stell( stream ) - startPos;
	sseek( stream, startPos );
	return( length );
	}

int getStreamObjectLength( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	return( findObjectLength( stream, FALSE ) );
	}

int getObjectLength( const void *objectPtr, const int objectLength )
	{
	STREAM stream;
	int length;

	assert( isReadPtr( objectPtr, objectLength ) );
	assert( objectLength > 0 );

	sMemConnect( &stream, objectPtr, objectLength );
	if( peekTag( &stream ) == BER_INTEGER )
		{
		int status;

		/* Sometimes we're asked to find the length of non-hole items that 
		   will be rejected by findObjectLength(), which calls down to 
		   readGenericHoleI().  Since these items are primitive and non-
		   constructed (in order to qualify as non-holes), we can process 
		   the item with readUniversal().
		   
		   An alternative processing mechanism would be to use peekTag() and
		   readGenericHole() in combination with the peekTag() results */
		status = length = readUniversal( &stream );
		if( cryptStatusOK( status ) )
			length = stell( &stream );
		}
	else
		length = findObjectLength( &stream, FALSE );
	sMemDisconnect( &stream );

	return( length );
	}

long getLongObjectLength( const void *objectPtr, const long objectLength )
	{
	STREAM stream;
	int length;

	assert( isReadPtr( objectPtr, objectLength ) );
	assert( objectLength > 0 );

	sMemConnect( &stream, objectPtr, objectLength );
	length = findObjectLength( &stream, TRUE );
	sMemDisconnect( &stream );

	return( length );
	}
