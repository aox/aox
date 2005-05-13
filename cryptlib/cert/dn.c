/****************************************************************************
*																			*
*							Certificate DN Routines							*
*						Copyright Peter Gutmann 1996-2002					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
#elif defined( INC_CHILD )
  #include "cert.h"
  #include "../misc/asn1.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* DN component info flags.  Some implementations may place more than one
   AVA into a RDN.  In this case we set a flag to indicate that the RDN
   continues in the next DN component structure.  If the RDN/DN was set by
   specifying the entire DN at once using a free-format text DN string, it's
   not a good idea to allow random changes to it so we mark the components
   as locked.  If we're reading data from an external source the DN can
   contain all sorts of strange stuff, so we set a flag to tell the DN
   component-handling code not to perform any validity checking on the
   components as they're added */

#define DN_FLAG_CONTINUED	0x01	/* RDN continues with another AVA */
#define DN_FLAG_LOCKED		0x02	/* RDN can't be modified */
#define DN_FLAG_PREENCODED	0x04	/* RDN has had pre-encoding done */
#define DN_FLAG_NOCHECK		0x08	/* Don't check validity of components */

/* The structure to hold a DN component */

typedef struct DC {
	/* DN component type and type information */
	CRYPT_ATTRIBUTE_TYPE type;		/* cryptlib component type */
	const void *typeInfo;			/* Type info for this component */
	int flags;

	/* DN component data */
	void *value;					/* DN component value */
	int valueLength;				/* DN component value length */
	int valueStringType;			/* DN component native string type */

	/* Encoding information: The native string type (used for conversion to
	   ASN.1 string type when encoding), the encodede string type, the 
	   overall size of the RDN data (without the tag and length) if this is 
	   the first or only component of an RDN, and the size of the AVA data */
	int encodingStringType, encodedStringType;
	int encodedRDNdataSize, encodedAVAdataSize;

	/* The next and previous list element in the linked list of DN
	   components */
	struct DC *next, *prev;

	/* Variable-length storage for the DN data */
	DECLARE_VARSTRUCT_VARS;
	} DN_COMPONENT;

/****************************************************************************
*																			*
*							DN Information Tables							*
*																			*
****************************************************************************/

/* The sort order for DN components */

static int dnSortTable[] = {
	0,								/* countryName */
	1,								/* stateOrProvinceName */
	2,								/* locationName */
	3,								/* organizationName */
	4,								/* organizationalUnitName */
	5								/* commonName */
	};

#define dnSortOrder( value )	\
		dnSortTable[ ( value ) - CRYPT_CERTINFO_COUNTRYNAME ]

/* A macro to make make declaring DN OID's simpler */

#define MKDNOID( value )	( ( const BYTE * ) "\x06\x03" value )

/* Type information for DN components */

typedef struct {
	const CRYPT_ATTRIBUTE_TYPE type;/* cryptlib type */
	const BYTE *oid;				/* OID for this type */
	const char *name, *altName;		/* Name for this type */
	const int maxLength;			/* Maximum allowed length for this type */
	const BOOLEAN ia5OK;			/* Whether IA5 is allowed for this comp.*/
	const BOOLEAN wcsOK;			/* Whether widechar is allowed for comp.*/
	} DN_COMPONENT_INFO;

static const FAR_BSS DN_COMPONENT_INFO certInfoOIDs[] = {
	/* Useful components */
	{ CRYPT_CERTINFO_COMMONNAME, MKDNOID( "\x55\x04\x03" ), "cn", "oid.2.5.4.3", CRYPT_MAX_TEXTSIZE, FALSE, TRUE },
	{ CRYPT_CERTINFO_COUNTRYNAME, MKDNOID( "\x55\x04\x06" ), "c", "oid.2.5.4.6", 2, FALSE, FALSE },
	{ CRYPT_CERTINFO_LOCALITYNAME, MKDNOID( "\x55\x04\x07" ), "l", "oid.2.5.4.7", 128, FALSE, TRUE },
	{ CRYPT_CERTINFO_STATEORPROVINCENAME, MKDNOID( "\x55\x04\x08" ), "sp", "oid.2.5.4.8", 128, FALSE, TRUE },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, MKDNOID( "\x55\x04\x0A" ), "o", "oid.2.5.4.10", CRYPT_MAX_TEXTSIZE, FALSE, TRUE },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, MKDNOID( "\x55\x04\x0B" ), "ou", "oid.2.5.4.11", CRYPT_MAX_TEXTSIZE, FALSE, TRUE },

	/* Non-useful components */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x01" ), "oid.2.5.4.1", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* aliasObjectName (2 5 4 1) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x02" ), "oid.2.5.4.2", NULL, MAX_ATTRIBUTE_SIZE /*32768*/, FALSE, FALSE },
							/* knowledgeInformation (2 5 4 2) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x04" ), "s", "oid.2.5.4.4", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* surname (2 5 4 4) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x05" ), "sn", "oid.2.5.4.5", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* serialNumber (2 5 4 5) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x09" ), "st", "oid.2.5.4.9", 128, FALSE, FALSE },
							/* streetAddress (2 5 4 9) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x0C" ), "t", "oid.2.5.4.12", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* title (2 5 4 12) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x0D" ), "d", "oid.2.5.4.13", 1024, FALSE, FALSE },
							/* description (2 5 4 13) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x0E" ), "oid.2.5.4.14", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* searchGuide (2 5 4 14) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x0F" ), "bc", "oid.2.5.4.15", 128, FALSE, FALSE },
							/* businessCategory (2 5 4 15) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x10" ), "oid.2.5.4.16", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* postalAddress (2 5 4 16) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x11" ), "oid.2.5.4.17", NULL, 40, FALSE, FALSE },
							/* postalCode (2 5 4 17) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x12" ), "oid.2.5.4.18", NULL, 40, FALSE, FALSE },
							/* postOfficeBox (2 5 4 18) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x13" ), "oid.2.5.4.19", NULL, 128, FALSE, FALSE },
							/* physicalDeliveryOfficeName (2 5 4 19) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x14" ), "oid.2.5.4.20", NULL, 32, FALSE, FALSE },
							/* telephoneNumber (2 5 4 20) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x15" ), "oid.2.5.4.21", NULL, 14, FALSE, FALSE },
							/* telexNumber (2 5 4 21) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x16" ), "oid.2.5.4.22", NULL, 24, FALSE, FALSE },
							/* teletexTerminalIdentifier (2 5 4 22) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x17" ), "oid.2.5.4.23", NULL, 32, FALSE, FALSE },
							/* facsimileTelephoneNumber (2 5 4 23) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x18" ), "oid.2.5.4.24", NULL, 15, FALSE, FALSE },
							/* x121Address (2 5 4 24) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x19" ), "isdn", "oid.2.5.4.25", 16, FALSE, FALSE },
							/* internationalISDNNumber (2 5 4 25) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x1A" ), "oid.2.5.4.26", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* registeredAddress (2 5 4 26) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x1B" ), "oid.2.5.4.27", NULL, 128, FALSE, FALSE },
							/* destinationIndicator (2 5 4 27) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x1C" ), "oid.2.5.4.28", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* preferredDeliveryMethod (2 5 4 28) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x1D" ), "oid.2.5.4.29", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* presentationAddress (2 5 4 29) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x1E" ), "oid.2.5.4.30", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* supportedApplicationContext (2 5 4 30) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x1F" ), "oid.2.5.4.31", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* member (2 5 4 31) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x20" ), "oid.2.5.4.32", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* owner (2 5 4 32) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x21" ), "oid.2.5.4.33", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* roleOccupant (2 5 4 33) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x22" ), "oid.2.5.4.34", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* seeAlso (2 5 4 34) */
							/* 0x23-0x28 are certs/CRLs and some weird encrypted directory components */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x29" ), "oid.2.5.4.41", NULL, MAX_ATTRIBUTE_SIZE /*32768*/, FALSE, FALSE },
							/* name (2 5 4 41) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x2A" ), "g", "oid.2.5.4.42", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* givenName (2 5 4 42) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x2B" ), "i", "oid.2.5.4.43", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* initials (2 5 4 43) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x2C" ), "oid.2.5.4.44", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* generationQualifier (2 5 4 44) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x2D" ), "oid.2.5.4.45", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* uniqueIdentifier (2 5 4 45) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x2E" ), "oid.2.5.4.46", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* dnQualifier (2 5 4 46) */
							/* 0x2F-0x30 are directory components */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x31" ), "oid.2.5.4.49", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* distinguishedName (2 5 4 49) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x32" ), "oid.2.5.4.50", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* uniqueMember (2 5 4 50) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x33" ), "oid.2.5.4.51", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* houseIdentifier (2 5 4 51) */
							/* 0x34-0x3A are more certs and weird encrypted directory components */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x41" ), "oid.2.5.4.65", NULL, 128, FALSE, FALSE },
							/* pseudonym (2 5 4 65) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x42" ), "oid.2.5.4.66", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* communicationsService (2 5 4 66) */
	{ CRYPT_ATTRIBUTE_NONE, MKDNOID( "\x55\x04\x43" ), "oid.2.5.4.67", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
							/* communicationsNetwork (2 5 4 67) */
							/* 0x44-0x49 are more PKI-related attributes */
	{ CRYPT_ATTRIBUTE_NONE, ( const BYTE * ) "\x06\x0A\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x01", "uid", NULL, CRYPT_MAX_TEXTSIZE, TRUE, FALSE },
							/* userid (0 9 2342 19200300 100 1 1) */
	{ CRYPT_ATTRIBUTE_NONE, ( const BYTE * ) "\x06\x0A\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x03", "oid.0.9.2342.19200300.100.1.3", NULL, CRYPT_MAX_TEXTSIZE, TRUE, FALSE },
							/* rfc822Mailbox (0 9 2342 19200300 100 1 3) */
	{ CRYPT_ATTRIBUTE_NONE, ( const BYTE * ) "\x06\x0A\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x19", "dc", "oid.0.9.2342.19200300.100.1.25", CRYPT_MAX_TEXTSIZE, TRUE, FALSE },
							/* domainComponent (0 9 2342 19200300 100 1 25) */
	{ CRYPT_ATTRIBUTE_NONE, ( const BYTE * ) "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01", "email", "oid.1.2.840.113549.1.9.1", CRYPT_MAX_TEXTSIZE, TRUE, FALSE },
							/* emailAddress (1 2 840 113549 1 9 1) */
	{ CRYPT_ATTRIBUTE_NONE, ( const BYTE * ) "\x06\x07\x02\x82\x06\x01\x0A\x07\x14", "oid.0.2.262.1.10.7.20", NULL, CRYPT_MAX_TEXTSIZE, TRUE, FALSE },
							/* nameDistinguisher (0 2 262 1 10 7 20) */

	{ CRYPT_ATTRIBUTE_NONE, NULL }
	} ;

/* If the OID doesn't correspond to a valid cryptlib component (i.e. it's one
   of the 1,001 other odd things which can be crammed into a DN), we can't
   directly identify it with a type but instead return the index in the OID
   info table, offset by a suitable amount */

#define DN_OID_OFFSET	10000

/* Check that a country code is valid */

#define xA	( 1 << 0 )
#define xB	( 1 << 1 )
#define xC	( 1 << 2 )
#define xD	( 1 << 3 )
#define xE	( 1 << 4 )
#define xF	( 1 << 5 )
#define xG	( 1 << 6 )
#define xH	( 1 << 7 )
#define xI	( 1 << 8 )
#define xJ	( 1 << 9 )
#define xK	( 1 << 10 )
#define xL	( 1 << 11 )
#define xM	( 1 << 12 )
#define xN	( 1 << 13 )
#define xO	( 1 << 14 )
#define xP	( 1 << 15 )
#define xQ	( 1 << 16 )
#define xR	( 1 << 17 )
#define xS	( 1 << 18 )
#define xT	( 1 << 19 )
#define xU	( 1 << 20 )
#define xV	( 1 << 21 )
#define xW	( 1 << 22 )
#define xX	( 1 << 23 )
#define xY	( 1 << 24 )
#define xZ	( 1 << 25 )

static BOOLEAN checkCountryCode( const char *countryCode )
	{
	static const long countryCodes[] = {	/* ISO 3166 code table */
	/*	 A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z */
  /*A*/			 xD|xE|xF|xG|	xI|		 xL|xM|xN|xO|	xQ|xR|xS|xT|xU|	  xW|	   xZ,
  /*B*/	xA|xB|	 xD|xE|xF|xG|xH|xI|xJ|		xM|xN|xO|	   xR|xS|xT|   xV|xW|	xY|xZ,
  /*C*/	xA|	  xC|xD|   xF|xG|xH|xI|	  xK|xL|xM|xN|xO|	   xR|		xU|xV|	 xX|xY|xZ,
  /*D*/				xE|			   xJ|xK|	xM|	  xO|							   xZ,
  /*E*/		  xC|	xE|	  xG|xH|						   xR|xS|xT,
  /*F*/							xI|xJ|xK|	xM|	  xO|	   xR,
  /*G*/	xA|xB|	 xD|xE|xF|	 xH|xI|		 xL|xM|xN|	 xP|xQ|xR|xS|xT|xU|	  xW|	xY,
  /*H*/								  xK|	xM|xN|		   xR|	 xT|xU,
  /*I*/			 xD|xE|					 xL|   xN|xO|	xQ|xR|xS|xT,
  /*J*/										xM|	  xO|xP,
  /*K*/				xE|	  xG|xH|xI|			xM|xN|	 xP|   xR|			  xW|	xY|xZ,
  /*L*/	xA|xB|xC|				xI|	  xK|				   xR|xS|xT|xU|xV|		xY,
  /*M*/	xA|	  xC|xD|	  xG|xH|	  xK|xL|xM|xN|xO|xP|xQ|xR|xS|xT|xU|xV|xW|xX|xY|xZ,
  /*N*/	xA|	  xC|	xE|xF|xG|	xI|		 xL|	  xO|xP|   xR|		xU|			   xZ,
  /*O*/										xM,
  /*P*/	xA|			xE|xF|xG|xH|	  xK|xL|xM|xN|		   xR|xS|xT|	  xW|	xY,
  /*Q*/	xA,
  /*R*/				xE|							  xO|				xU|	  xW,
  /*S*/	xA|xB|xC|xD|xE|	  xG|xH|xI|xJ|xK|xL|xM|xN|xO|	   xR|	 xT|   xV|		xY|xZ,
  /*T*/		  xC|xD|   xF|xG|xH|   xJ|xK|xL|xM|xN|xO|	   xR|	 xT|   xV|xW|	   xZ,
  /*U*/	xA|				  xG|				xM|				  xS|				xY|xZ,
  /*V*/	xA|	  xC|	xE|	  xG|	xI|			   xN|					xU,
  /*W*/				   xF|									  xS,
  /*X*/	0,
  /*Y*/				xE|											 xT|xU,
  /*Z*/	xA|									xM|							  xW,
		0, 0	/* Catch overflows */
		};
	const int cc0 = countryCode[ 0 ] - 'A';
	const int cc1 = countryCode[ 1 ] - 'A';

	/* Check that the country code is present in the table of valid ISO 3166
	   codes */
	if( cc0 < 0 || cc0 > 25 || cc1 < 0 || cc1 > 25 )
		return( FALSE );
	return( ( countryCodes[ cc0 ] & ( 1 << cc1 ) ) ? TRUE : FALSE );
	}

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Find a DN component in a DN component list by type and by OID */

static DN_COMPONENT *findDNComponent( const void *dnListHead,
									  const CRYPT_ATTRIBUTE_TYPE type,
									  const void *value,
									  const int valueLength )
	{
	DN_COMPONENT *listPtr = ( DN_COMPONENT * ) dnListHead;

	/* Find the position of this component in the list */
	while( listPtr != NULL )
		{
		assert( isReadPtr( listPtr, sizeof( DN_COMPONENT ) ) );

		if( listPtr->type == type && \
			( ( value == NULL ) || \
			  ( listPtr->valueLength == valueLength && \
				!memcmp( listPtr->value, value, valueLength ) ) ) )
			break;
		listPtr = listPtr->next;
		}

	return( listPtr );
	}

static DN_COMPONENT *findDNComponentByOID( const void *dnListHead,
										   const BYTE *oid )
	{
	DN_COMPONENT *listPtr = ( DN_COMPONENT * ) dnListHead;
	const int oidLen = sizeofOID( oid );

	/* Find the position of this component in the list */
	while( listPtr != NULL )
		{
		const DN_COMPONENT_INFO *dnComponentInfo = listPtr->typeInfo;

		if( !memcmp( dnComponentInfo->oid, oid, oidLen ) )
			break;
		listPtr = listPtr->next;
		}

	return( listPtr );
	}

/****************************************************************************
*																			*
*								Insert/Delete DNs							*
*																			*
****************************************************************************/

/* Insert a DN component into a list.  If the type is zero then it's an
   unrecognised component type, and if it's negative it's a recognised
   component type being read from a cert produced by a non-cryptlib
   application.  In this case we don't try to sort the component into the
   correct position */

static int insertDNstring( void **dnListHead, const CRYPT_ATTRIBUTE_TYPE type,
						   const void *value, const int valueLength,
						   const int flags, CRYPT_ERRTYPE_TYPE *errorType )
	{
	const DN_COMPONENT_INFO *dnComponentInfo;
	DN_COMPONENT *listHeadPtr = *dnListHead;
	DN_COMPONENT *newElement, *insertPoint;

	/* If the DN is locked against modification we can't make any further
	   updates */
	if( listHeadPtr != NULL && listHeadPtr->flags & DN_FLAG_LOCKED )
		return( CRYPT_ERROR_INITED );

	/* Find the type information for this component if it's a recognised
	   type */
	if( type > CRYPT_CERTINFO_FIRST && type < CRYPT_CERTINFO_LAST )
		{
		int i;

		/* It's a handled component, get the pointer to the OID */
		for( i = 0; certInfoOIDs[ i ].type != CRYPT_ATTRIBUTE_NONE; i++ )
			if( certInfoOIDs[ i ].type == type )
				{
				dnComponentInfo = &certInfoOIDs[ i ];
				break;
				}
		if( certInfoOIDs[ i ].type == CRYPT_ATTRIBUTE_NONE )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
			}
		}
	else
		/* It's a non-handled component, the type is an index into the
		   component table.  At this point we run into a GCC 2.7.x compiler
		   bug (detect with '#if defined( __GNUC__ ) && ( __GNUC__ == 2 )').
		   If we use the expression '&certInfoOIDs[ type - DN_OID_OFFSET ]'
		   what we should get is:
				leal -1000(%ebp,%ebp,2),%eax
				movl certInfoOIDs(,%eax,4),%eax
		   but what we actually get is:
				leal -3000(%ebp,%ebp,2),%eax
				movl certInfoOIDs(,%eax,4),%eax
		   To fix this we need to insert some form of dummy evaluation in a
		   form which ensures that it can't be optimised away (which is
		   actually quite difficult with gcc because it optimises any simple
		   code way).  To work around this we insert a dummy expression to
		   keep the value live */
		{
#if defined( __GNUC__ ) && ( __GNUC__ == 2 )
		int i = type - DN_OID_OFFSET;
		dnComponentInfo = &certInfoOIDs[ i ];
		if( dnComponentInfo < 0 )	/* Dummy code to keep i live */
			newElement = ( i + type ) ? NULL : ( void * ) value;
#else
		dnComponentInfo = &certInfoOIDs[ type - DN_OID_OFFSET ];
#endif /* gcc 2.7.x bug workaround */
		if( type - DN_OID_OFFSET >= \
			sizeof( certInfoOIDs ) / sizeof( DN_COMPONENT_INFO ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
			}
		}

	/* Make sure that the length is valid.  If it's being read from an
	   encoded form we allow abnormally-long lengths (although we still keep
	   them within a sensible limit) since this is better than failing to
	   read a cert because it contains a broken DN.  In addition if a
	   widechar string is OK we allow a range up to the maximum byte count
	   defined by the widechar size, this is only valid for standard DN
	   components, when they're coming from the user the exact check has
	   already been performed by the kernel */
#ifdef USE_WIDECHARS
	if( valueLength > ( ( flags & DN_FLAG_NOCHECK ) ? \
							MAX_ATTRIBUTE_SIZE : \
						( dnComponentInfo->wcsOK ) ? \
							( WCSIZE * dnComponentInfo->maxLength ) : \
							dnComponentInfo->maxLength ) )
#else
	if( valueLength > ( ( flags & DN_FLAG_NOCHECK ) ? \
							MAX_ATTRIBUTE_SIZE : dnComponentInfo->maxLength ) )
#endif /* USE_WIDECHARS */
		{
		if( errorType != NULL )
			*errorType = CRYPT_ERRTYPE_ATTR_SIZE;
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* Find the correct place in the list to insert the new element */
	if( listHeadPtr != NULL )
		{
		DN_COMPONENT *prevElement = NULL;

		/* If it's being read from an external cert item, just append it to
		   the end of the list */
		if( flags & DN_FLAG_NOCHECK )
			for( insertPoint = listHeadPtr; insertPoint->next != NULL;
				 insertPoint = insertPoint->next );
		else
			{
			for( insertPoint = listHeadPtr; insertPoint != NULL && \
				 dnSortOrder( type ) >= dnSortOrder( insertPoint->type );
				 insertPoint = insertPoint->next )
				{
				/* Make sure this component isn't already present.  For now
				   we only allow a single DN component of any type to keep
				   things simple for the user, if it's necessary to allow
				   multiple components of the same type we need to check the
				   value and valueLength as well */
				if( insertPoint->type == type )
					{
					if( errorType != NULL )
						*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
					return( CRYPT_ERROR_INITED );
					}

				prevElement = insertPoint;
				}
			insertPoint = prevElement;
			}
		}

	/* Allocate memory for the new element and copy over the information */
	if( ( newElement = ( DN_COMPONENT * ) \
				clAlloc( "insertDNstring", sizeof( DN_COMPONENT ) + \
										   valueLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	initVarStruct( newElement, DN_COMPONENT, valueLength );
	newElement->type = type;
	newElement->typeInfo = dnComponentInfo;
	memcpy( newElement->value, value, valueLength );
	newElement->valueLength = valueLength;
	newElement->flags = flags;

	/* If it's a country code, force it to uppercase as per ISO 3166 */
	if( type == CRYPT_CERTINFO_COUNTRYNAME )
		{
		BYTE *dnStrPtr = newElement->value;

		dnStrPtr[ 0 ] = toUpper( dnStrPtr[ 0 ] );
		dnStrPtr[ 1 ] = toUpper( dnStrPtr[ 1 ] );

		if( flags & DN_FLAG_NOCHECK )
			{
			/* 'UK' isn't an ISO 3166 country code but may be found in some
			   certificates.  If we find this, we quietly convert it to the
			   correct value */
			if( !memcmp( newElement->value, "UK", 2 ) )
				memcpy( newElement->value, "GB", 2 );
			}
		else
			/* Make sure the country code is valid */
			if( !checkCountryCode( ( char * ) newElement->value ) )
				{
				endVarStruct( newElement, DN_COMPONENT );
				clFree( "insertDNstring", newElement );
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ERROR_INVALID );
				}

		}

	/* Link it into the list */
	insertDoubleListElement( ( DN_COMPONENT ** ) dnListHead, insertPoint,
							 newElement );

	return( CRYPT_OK );
	}

int insertDNComponent( void **dnListHead,
					   const CRYPT_ATTRIBUTE_TYPE type,
					   const void *value, const int valueLength,
					   CRYPT_ERRTYPE_TYPE *errorType )
	{
	return( insertDNstring( dnListHead, type, value, valueLength, 0,
							errorType ) );
	}

/* Delete a DN component from a list */

static int deleteComponent( void **dnListHead, DN_COMPONENT *theElement )
	{
	DN_COMPONENT *listPrevPtr, *listNextPtr;

	if( theElement == NULL )
		return( CRYPT_ERROR_NOTFOUND );
	assert( isWritePtr( theElement, sizeof( DN_COMPONENT ) ) );
	listPrevPtr = theElement->prev;
	listNextPtr = theElement->next;

	/* Remove the item from the list */
	if( theElement == *dnListHead )
		*dnListHead = listNextPtr;			/* Delete from start */
	else
		listPrevPtr->next = listNextPtr;	/* Delete from middle or end */
	if( listNextPtr != NULL )
		listNextPtr->prev = listPrevPtr;

	/* Clear all data in the list item and free the memory */
	endVarStruct( theElement, DN_COMPONENT );
	clFree( "deleteComponent", theElement );

	return( CRYPT_OK );
	}

int deleteDNComponent( void **dnListHead,
					   const CRYPT_ATTRIBUTE_TYPE type, const void *value,
					   const int valueLength )
	{
	DN_COMPONENT *listHeadPtr = *dnListHead;

	/* If the DN is locked against modification we can't make any further
	   updates */
	if( listHeadPtr != NULL && listHeadPtr->flags & DN_FLAG_LOCKED )
		return( CRYPT_ERROR_PERMISSION );

	/* Find the component in the list and delete it */
	return( deleteComponent( dnListHead, findDNComponent( listHeadPtr, type,
													value, valueLength ) ) );
	}

/* Delete a DN */

void deleteDN( void **dnListHead )
	{
	DN_COMPONENT *listPtr = *dnListHead;

	/* Mark the list as being empty */
	*dnListHead = NULL;

	/* Destroy all DN items */
	while( listPtr != NULL )
		{
		DN_COMPONENT *itemToFree = listPtr;

		listPtr = listPtr->next;
		deleteComponent( ( void ** ) &itemToFree, itemToFree );
		}
	}

/* Get the value of a DN component */

int getDNComponentValue( const void *dnListHead,
						 const CRYPT_ATTRIBUTE_TYPE type,
						 void *value, int *length, const int maxLength )
	{
	const DN_COMPONENT *dnComponent = findDNComponent( dnListHead, type,
													   NULL, 0 );

	if( dnComponent == NULL )
		return( CRYPT_ERROR_NOTFOUND );
	*length = dnComponent->valueLength;
	if( value == NULL )
		return( CRYPT_OK );
	if( dnComponent->valueLength > maxLength )
		return( CRYPT_ERROR_OVERFLOW );
	if( !isWritePtr( value, dnComponent->valueLength ) )
		return( CRYPT_ARGERROR_STR1 );
	memcpy( value, dnComponent->value, dnComponent->valueLength );
	return( CRYPT_OK );
	}

/* Compare two DNs.  Since this is used for constraint comparisons as well
   as just strict equality checks, we provide a flag which, if set, returns
   a match if the first DN is a proper substring of the second DN */

BOOLEAN compareDN( const void *dnComponentListHead1,
				   const void *dnComponentListHead2,
				   const BOOLEAN dn1substring )
	{
	DN_COMPONENT *dn1ptr = ( DN_COMPONENT * ) dnComponentListHead1;
	DN_COMPONENT *dn2ptr = ( DN_COMPONENT * ) dnComponentListHead2;

	/* Check each DN component for equality */
	while( dn1ptr != NULL && dn2ptr != NULL )
		{
		/* If the RDN types differ, the DNs don't match */
		if( dn1ptr->type != dn2ptr->type )
			return( FALSE );

		/* Compare the current RDNs.  In theory we should be using the
		   complex and arcane X.500 name comparison rules, but no-one
		   actually does this since they're almost impossible to get right.
		   Since everyone else uses memcpy()/memcmp() to handle DN
		   components, it's safe to use it here (sic faciunt omnes).  This 
		   also avoids any potential security problems arising from the 
		   complexity of the code necessary to implement the X.500 matching 
		   rules */
		if( dn1ptr->valueLength != dn2ptr->valueLength || \
			memcmp( dn1ptr->value, dn2ptr->value, dn1ptr->valueLength ) )
			return( FALSE );

		/* Move on to the next component */
		dn1ptr = dn1ptr->next;
		dn2ptr = dn2ptr->next;
		}

	/* If we've reached the end of both DNs or we're looking for a substring
	   match, the two match */
	return( ( ( dn1ptr == NULL && dn2ptr == NULL ) || dn1substring ) ? \
			TRUE : FALSE );
	}

/* Copy a DN */

int copyDN( void **dnDest, const void *dnSrc )
	{
	const DN_COMPONENT *srcPtr;
	DN_COMPONENT *destPtr = NULL;

	/* Clear return value */
	*dnDest = NULL;

	/* Copy each element in the source DN */
	for( srcPtr = dnSrc; srcPtr != NULL; srcPtr = srcPtr->next )
		{
		DN_COMPONENT *newElement;

		/* Allocate memory for the new element and copy over the information */
		if( ( newElement = ( DN_COMPONENT * ) \
					clAlloc( "copyDN", \
					sizeofVarStruct( srcPtr, DN_COMPONENT ) ) ) == NULL )
			{
			deleteDN( dnDest );
			return( CRYPT_ERROR_MEMORY );
			}
		copyVarStruct( newElement, srcPtr, DN_COMPONENT );

		/* Link it into the list */
		if( destPtr == NULL )
			{
			*dnDest = destPtr = newElement;
			newElement->prev = newElement->next = NULL;
			}
		else
			{
			newElement->prev = destPtr;
			newElement->next = NULL;
			destPtr->next = newElement;
			destPtr = newElement;
			}
		}

	return( CRYPT_OK );
	}

/* Check the validity of a DN.  The check for the bottom of the DN (common
   name) and top (country) are made configurable, DNs which act as filters
   (e.g. path constraints) may not have the lower DN parts present, and cert
   requests submitted to CAs which set the country themselves may not have
   the country present */

int checkDN( const void *dnComponentListHead,
			 const BOOLEAN checkCN, const BOOLEAN checkC,
			 CRYPT_ATTRIBUTE_TYPE *errorLocus,
			 CRYPT_ERRTYPE_TYPE *errorType )
	{
	DN_COMPONENT *dnComponentListPtr;
	BOOLEAN hasCountry = TRUE, hasCommonName = FALSE;

	/* Clear the return values */
	*errorType = CRYPT_OK;
	*errorLocus = CRYPT_ATTRIBUTE_NONE;

	/* Make sure that certain critical components are present */
	for( dnComponentListPtr = ( DN_COMPONENT * ) dnComponentListHead;
		 dnComponentListPtr != NULL;
		 dnComponentListPtr = dnComponentListPtr->next )
		{
		if( dnComponentListPtr->type == CRYPT_CERTINFO_COUNTRYNAME )
			{
			if( !checkCountryCode( ( char * ) dnComponentListPtr->value ) )
				{
				*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				*errorLocus = CRYPT_CERTINFO_COUNTRYNAME;
				return( CRYPT_ERROR_INVALID );
				}
			hasCountry = TRUE;
			}
		if( dnComponentListPtr->type == CRYPT_CERTINFO_COMMONNAME )
			hasCommonName = TRUE;
		}
	if( ( checkC && !hasCountry ) || ( checkCN && !hasCommonName ) )
		{
		*errorType = CRYPT_ERRTYPE_ATTR_ABSENT;
		*errorLocus = ( hasCountry ) ? CRYPT_CERTINFO_COMMONNAME : \
									   CRYPT_CERTINFO_COUNTRYNAME;
		return( CRYPT_ERROR_NOTINITED );
		}

	return( CRYPT_OK );
	}

/* Convert a DN component containing a PKCS #9 emailAddress or an RFC 1274
   rfc822Mailbox into an rfc822Name */

int convertEmail( CERT_INFO *certInfoPtr, void **dnListHead,
				  const CRYPT_ATTRIBUTE_TYPE altNameType )
	{
	DN_COMPONENT *emailComponent = findDNComponentByOID( *dnListHead,
			( const BYTE * ) "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01" );
	SELECTION_STATE selectionState;
	void *certDataPtr;
	int status;

	/* If there's no PKCS #9 email address present, try for an RFC 1274 one.
	   If that's not present either, exit */
	if( emailComponent == NULL )
		{
		emailComponent = findDNComponentByOID( *dnListHead,
			( const BYTE * ) "\x06\x09\x09\x92\x26\x89\x93\xF2\x2C\x01\x03" );
		if( emailComponent == NULL )
			return( CRYPT_OK );
		}

	/* Try and add the email address component as an rfc822Name.  Since this
	   changes the current GeneralName selection, we have to be careful about
	   saving and restoring the state.  In addition since we're changing the
	   internal state of an object which is technically in the high state, we
	   have to temporarily disconnect the cert data from the cert object to
	   make it appear as a mutable object.  This is an unfortunate
	   consequence of the fact that what we're doing is a behind-the-scenes
	   switch to move a cert component from where it is to where it really
	   should be */
	saveSelectionState( selectionState, certInfoPtr );
	certDataPtr = certInfoPtr->certificate;
	certInfoPtr->certificate = NULL;
	status = addCertComponent( certInfoPtr, CRYPT_ATTRIBUTE_CURRENT,
							   &altNameType, 0 );
	assert( cryptStatusOK( status ) );
	status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_RFC822NAME,
							   emailComponent->value,
							   emailComponent->valueLength );
	if( cryptStatusOK( status ) )
		/* It was successfully copied over, delete the copy in the DN */
		deleteComponent( dnListHead, emailComponent );
	else
		{
		/* If it's already present (which is somewhat odd since the presence
		   of an email address in the DN implies that the implementation
		   doesn't know about rfc822Name) we can't do anything about it */
		if( status == CRYPT_ERROR_INITED )
			status = CRYPT_OK;
		else
			/* Some certs can contain garbage in the (supposed) email 
			   address, normally the cert would be rejected because of this 
			   but if we're running in oblivious mode we can import it 
			   successfully but then get an internal error code when we try 
			   and perform this sideways add.  To catch this, we check for 
			   invalid email addresses here and ignore an error status if
			   we get one */
			if( cryptArgError( status ) )
				status = CRYPT_OK;
		}
	certInfoPtr->certificate = certDataPtr;
	restoreSelectionState( selectionState, certInfoPtr );

	return( status );
	}

/****************************************************************************
*																			*
*									Read a DN								*
*																			*
****************************************************************************/

/* Parse an AVA.   This determines the AVA type and leaves the stream pointer
   at the start of the data value */

static int readAVA( STREAM *stream, CRYPT_ATTRIBUTE_TYPE *type, int *length,
					int *stringTag )
	{
	BYTE oid[ MAX_OID_SIZE ];
	int oidLength, tag, i, status;

	/* Clear return values */
	*type = CRYPT_ATTRIBUTE_NONE;
	*length = 0;
	*stringTag = 0;

	/* Read the start of the AVA and determine the type from the AttributeType
	   field.  If we find something which we don't recognise, we indicate it
	   as a non-component type which can be read or written but not directly
	   accessed by the user (although it can still be accessed using the
	   cursor functions) */
	readSequence( stream, NULL );
	status = readRawObject( stream, oid, &oidLength, MAX_OID_SIZE,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	for( i = 0; certInfoOIDs[ i ].oid != NULL; i++ )
		if( !memcmp( certInfoOIDs[ i ].oid, oid, oidLength ) )
			{
			*type = ( certInfoOIDs[ i ].type != CRYPT_ATTRIBUTE_NONE ) ?
					certInfoOIDs[ i ].type : i + DN_OID_OFFSET;
			break;
			}
	if( *type == CRYPT_ATTRIBUTE_NONE )
		{
		/* If we don't recognise the component type, skip it */
		readUniversal( stream );
		return( OK_SPECIAL );
		}

	/* We've reached the data value, make sure it's in order */
	tag = peekTag( stream );
	if( tag == BER_BITSTRING )
		{
		/* Bitstrings are used for uniqueIdentifiers, however these usually
		   encapsulate something else so we dig one level deeper to find the
		   encapsulated string */
		readBitStringHole( stream, NULL, DEFAULT_TAG );
		tag = peekTag( stream );
		}
	*stringTag = tag;
	return( readGenericHole( stream, length, tag ) );
	}

/* Read an RDN component */

static int readRDNcomponent( STREAM *stream, void **dnComponentListHead,
							 const int rdnDataLeft )
	{
	CRYPT_ATTRIBUTE_TYPE type;
	BYTE stringBuffer[ MAX_ATTRIBUTE_SIZE ], *value;
	const int rdnStart = stell( stream );
	int valueLength, stringTag;
	int flags = DN_FLAG_NOCHECK, status;

	/* Read the type information for this AVA */
	status = readAVA( stream, &type, &valueLength, &stringTag );
	if( cryptStatusError( status ) )
		return( status );
	value = sMemBufPtr( stream );
	if( valueLength <= 0 )
		/* Skip broken AVAs with zero-length strings */
		return( CRYPT_OK );
	status = sSkip( stream, valueLength );
	if( cryptStatusError( status ) )
		return( status );

	/* If there's room for another AVA, mark this one as being continued.  The
	   +10 is the minimum length for an AVA: SEQ { OID, value } (2-bytes SEQ +
	   5-bytes OID + 2-bytes tag + len + 1 byte min-length data).  We don't do
	   a simple =/!= check to get around incorrectly encoded lengths */
	if( rdnDataLeft >= ( stell( stream ) - rdnStart ) + 10 )
		flags |= DN_FLAG_CONTINUED;

	/* Convert the string into the local character set */
	status = copyFromAsn1String( stringBuffer, &valueLength,
								 MAX_ATTRIBUTE_SIZE, value, valueLength,
								 stringTag );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the DN component to the DN.  If we hit a non-memory related error
	   we turn it into a generic CRYPT_ERROR_BADDATA error, since the other
	   codes are somewhat too specific for this case (e.g. CRYPT_ERROR_INITED
	   or an arg error isn't too useful for the caller) */
	status = insertDNstring( dnComponentListHead, type, stringBuffer,
							 valueLength, flags, NULL );
	return( ( cryptStatusError( status ) && status != CRYPT_ERROR_MEMORY ) ? \
			CRYPT_ERROR_BADDATA : status );
	}

/* Read a DN */

int readDN( STREAM *stream, void **dnComponentListHead )
	{
	int length, status;

	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	while( length > 0 )
		{
		const int startPos = stell( stream );
		int rdnLength;

		/* Read the start of the RDN */
		status = readSet( stream, &rdnLength );
		if( cryptStatusError( status ) )
			return( status );

		/* Read each RDN component */
		while( rdnLength > 0 )
			{
			const int rdnStart = stell( stream );

			status = readRDNcomponent( stream, dnComponentListHead,
									   rdnLength );
			if( cryptStatusError( status ) && status != OK_SPECIAL )
				return( status );

			rdnLength -= stell( stream ) - rdnStart;
			}
		if( rdnLength < 0 )
			return( CRYPT_ERROR_BADDATA );

		length -= stell( stream ) - startPos;
		}
	if( length < 0 )
		return( CRYPT_ERROR_BADDATA );

	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*									Write a DN								*
*																			*
****************************************************************************/

/* Perform the pre-encoding processing for a DN */

static int preEncodeDN( DN_COMPONENT *dnComponentPtr )
	{
	int size = 0;

	if( dnComponentPtr == NULL )
		return( 0 );

	assert( isReadPtr( dnComponentPtr, sizeof( DN_COMPONENT ) ) );

	/* If we're being fed an entry in the middle of a DN, move back to the
	   start */
	while( dnComponentPtr->prev != NULL )
		dnComponentPtr = dnComponentPtr->prev;

	/* Walk down the DN pre-encoding each AVA */
	while( dnComponentPtr != NULL )
		{
		DN_COMPONENT *rdnStartPtr = dnComponentPtr;
		BOOLEAN isContinued;

		/* If this component has already had pre-encoding processing 
		   applied, there's no need to do it again */
		if( dnComponentPtr->flags & DN_FLAG_PREENCODED )
			{
			if( dnComponentPtr->encodedRDNdataSize > 0 )
				size += ( int ) sizeofObject( dnComponentPtr->encodedRDNdataSize );
			dnComponentPtr = dnComponentPtr->next;
			continue;
			}

		/* Calculate the size of every AVA in this RDN */
		do
			{
			const DN_COMPONENT_INFO *dnComponentInfo = dnComponentPtr->typeInfo;
			int dnStringLength, status;

			status = getAsn1StringInfo( dnComponentPtr->value, 
										dnComponentPtr->valueLength,
										&dnComponentPtr->valueStringType, 
										&dnComponentPtr->encodedStringType,
										&dnStringLength );
			if( cryptStatusError( status ) )
				return( status );
			dnComponentPtr->encodedAVAdataSize = ( int ) \
										sizeofOID( dnComponentInfo->oid ) + \
										sizeofObject( dnStringLength );
			dnComponentPtr->encodedRDNdataSize = 0;
			dnComponentPtr->flags |= DN_FLAG_PREENCODED;
			rdnStartPtr->encodedRDNdataSize += ( int ) \
						sizeofObject( dnComponentPtr->encodedAVAdataSize );
			isContinued = dnComponentPtr->flags & DN_FLAG_CONTINUED;
			dnComponentPtr = dnComponentPtr->next;
			}
		while( isContinued && dnComponentPtr != NULL );

		/* Calculate the overall size of the RDN */
		size += ( int ) sizeofObject( rdnStartPtr->encodedRDNdataSize );
		}

	return( size );
	}

int sizeofDN( void *dnComponentListHead )
	{
	return( sizeofObject( preEncodeDN( dnComponentListHead ) ) );
	}

/* Write a DN */

int writeDN( STREAM *stream, const void *dnComponentListHead, const int tag )
	{
	DN_COMPONENT *dnComponentPtr;
	const int size = preEncodeDN( ( DN_COMPONENT * ) dnComponentListHead );
	int status = CRYPT_OK;

	if( cryptStatusError( size ) )
		return( size );

	/* Write the DN */
	writeConstructed( stream, size, tag );
	for( dnComponentPtr = ( DN_COMPONENT * ) dnComponentListHead;
		 dnComponentPtr != NULL && cryptStatusOK( status );
		 dnComponentPtr = dnComponentPtr->next )
		{
		const DN_COMPONENT_INFO *dnComponentInfo = dnComponentPtr->typeInfo;
		BYTE dnString[ MAX_ATTRIBUTE_SIZE ];
		int dnStringLength;

		/* Write the RDN wrapper */
		if( dnComponentPtr->encodedRDNdataSize )
			/* If it's the start of an RDN, write the RDN header */
			writeSet( stream, dnComponentPtr->encodedRDNdataSize );
		writeSequence( stream, dnComponentPtr->encodedAVAdataSize );
		swrite( stream, dnComponentInfo->oid, \
				sizeofOID( dnComponentInfo->oid ) );

		/* Convert the string to an ASN.1-compatible format and write it
		   out */
		status = copyToAsn1String( dnString, &dnStringLength,
								MAX_ATTRIBUTE_SIZE, dnComponentPtr->value,
								dnComponentPtr->valueLength,
								dnComponentPtr->valueStringType );
		if( cryptStatusError( status ) )
			return( status );
		if( dnComponentPtr->encodedStringType == BER_STRING_IA5 && \
			!dnComponentInfo->ia5OK )
			/* If an IA5String isn't allowed in this instance, use a
			   T61String instead */
			dnComponentPtr->encodedStringType = BER_STRING_T61;
		status = writeCharacterString( stream, dnString, dnStringLength,
									   dnComponentPtr->encodedStringType );
		}

	return( status );
	}

/****************************************************************************
*																			*
*								DN String Routines							*
*																			*
****************************************************************************/

/* Read a DN in string form */

typedef struct {
	const char *label, *text;
	int labelLen, textLen;			/* DN component label and value */
	BOOLEAN isContinued;			/* Whether further AVAs in this RDN */
	} DN_STRING_INFO;

#define MAX_DNSTRING_COMPONENTS 64

static BOOLEAN parseDNString( DN_STRING_INFO *dnStringInfo,
							  const char *string, const int stringLength )
	{
	int stringPos = 0, stringInfoIndex = 0, i;

	memset( dnStringInfo, 0,
			sizeof( DN_STRING_INFO ) * ( MAX_DNSTRING_COMPONENTS + 1 ) );

	/* Make sure there are no control characters in the string */
	for( i = 0; i < stringLength; i++ )
		if( ( string[ i ] & 0x7F ) < ' ' )
			return( FALSE );

	/* Verify that a DN string is of the form:

		dnString ::= assignment '\0' | assignment ',' assignment
		assignment ::= label '=' text */
	do
		{
		DN_STRING_INFO *dnStringInfoPtr = &dnStringInfo[ stringInfoIndex ];

		/* Check for label '=' ... */
		for( i = stringPos; i < stringLength; i++ )
			{
			const char ch = string[ i ];

			if( ch == '\\' )
				return( FALSE );/* No escapes in the label component */
			if( ch == '=' || ch == ',' || ch == '+' )
				break;
			}
		if( i == stringPos || i == stringLength || \
			string[ i ] == ',' || string[ i ] == '+' )
			return( FALSE );	/* No text or no '=' or spurious ',' */
		dnStringInfoPtr->label = string + stringPos;
		dnStringInfoPtr->labelLen = i - stringPos;
		stringPos = i + 1;		/* Skip text + '=' */

		/* Check for ... text { '\0' | ',' ... | '+' ... } */
		for( i = stringPos;
			 i < stringLength && \
			 !( string[ i - 1 ] != '\\' && \
				( string[ i ] == ',' || string[ i ] == '+' || \
				  string[ i ] == '=' ) ); i++ );
		if( i == stringPos || string[ i ] == '=' )
			return( FALSE );	/* No text or spurious '=' */
		dnStringInfoPtr->text = string + stringPos;
		dnStringInfoPtr->textLen = i - stringPos;
		dnStringInfoPtr->isContinued = ( i < stringLength && \
										 string[ i ] == '+' ) ? TRUE : FALSE;
		stringPos = i;			/* Skip text + optional ',' */
		if( stringPos != stringLength && \
			++stringPos == stringLength )
			/* Trailing ',' */
			return( FALSE );

		/* Strip leading and trailing whitespace on the label and text */
		for( i = 0; i < dnStringInfoPtr->labelLen && \
					dnStringInfoPtr->label[ i ] == ' '; i++ );
		dnStringInfoPtr->label += i;
		dnStringInfoPtr->labelLen -= i;
		for( i = dnStringInfoPtr->labelLen; i > 0 && \
					dnStringInfoPtr->label[ i - 1 ] == ' '; i-- );
		dnStringInfoPtr->labelLen = i;
		for( i = 0; i < dnStringInfoPtr->textLen && \
					dnStringInfoPtr->text[ i ] == ' '; i++ );
		dnStringInfoPtr->text += i;
		dnStringInfoPtr->textLen -= i;
		for( i = dnStringInfoPtr->textLen; i > 0 && \
					dnStringInfoPtr->text[ i - 1 ] == ' '; i-- );
		dnStringInfoPtr->textLen = i;
		if( dnStringInfoPtr->labelLen <= 0 || dnStringInfoPtr->textLen <= 0 )
			return( FALSE );

		if( ++stringInfoIndex >= MAX_DNSTRING_COMPONENTS )
			return( FALSE );
		}
	while( stringPos < stringLength );

	return( TRUE );
	}

int readDNstring( const char *string, const int stringLength,
				  void **dnComponentListHead )
	{
	DN_STRING_INFO dnStringInfo[ MAX_DNSTRING_COMPONENTS + 1 ];
	DN_COMPONENT *dnComponentPtr;
	int stringInfoIndex;

	/* We have to perform the text string to DN translation in two stages
	   thanks to the backwards encoding required by RFC 1779, first we parse
	   it forwards to separate out the RDN components, then we move through
	   the parsed information backwards adding it to the RDN (with special
	   handling for multi-AVA RDNs as for writeDNstring()).  Overall this
	   isn't so bad because it means we can perform a general firewall check
	   to make sure the DN string is well-formed and then leave the encoding
	   as a separate pass */
	if( !parseDNString( dnStringInfo, string, stringLength ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Find the end of the DN components */
	for( stringInfoIndex = 0;
		 dnStringInfo[ stringInfoIndex + 1 ].label != NULL;
		 stringInfoIndex++ );

	do
		{
		const DN_STRING_INFO *dnStringInfoPtr;
		BOOLEAN isContinued;

		/* Find the start of the RDN */
		while( stringInfoIndex > 0 && \
			   dnStringInfo[ stringInfoIndex - 1 ].isContinued )
			stringInfoIndex--;
		dnStringInfoPtr = &dnStringInfo[ stringInfoIndex ];

		do
			{
			const DN_COMPONENT_INFO *dnComponentInfo = NULL;
			BYTE textBuffer[ MAX_ATTRIBUTE_SIZE + 1 ];
			CRYPT_ATTRIBUTE_TYPE type;
			int i, textIndex = 0, status;

			/* Look up the DN component information */
			for( i = 0; certInfoOIDs[ i ].oid != NULL; i++ )
				if( ( strlen( certInfoOIDs[ i ].name ) == \
										dnStringInfoPtr->labelLen && \
					  !strCompare( certInfoOIDs[ i ].name, dnStringInfoPtr->label,
								   dnStringInfoPtr->labelLen ) ) || \
					( certInfoOIDs[ i ].altName != NULL && \
					  strlen( certInfoOIDs[ i ].altName ) == \
										dnStringInfoPtr->labelLen && \
					  !strCompare( certInfoOIDs[ i ].altName, dnStringInfoPtr->label,
								   dnStringInfoPtr->labelLen ) ) )
					{
					dnComponentInfo = &certInfoOIDs[ i ];
					break;
					}
			if( dnComponentInfo == NULL )
				return( CRYPT_ARGERROR_STR1 );
			type = ( dnComponentInfo->type != CRYPT_ATTRIBUTE_NONE ) ?
				   dnComponentInfo->type : i + DN_OID_OFFSET;

			/* Convert the text to canonical form, removing any escapes for
			   special characters */
			for( i = 0; i < dnStringInfoPtr->textLen; i++ )
				{
				int ch = dnStringInfoPtr->text[ i ];

				if( ch == '\\' )
					{
					if( ++i >= dnStringInfoPtr->textLen )
						return( CRYPT_ARGERROR_STR1 );
					ch = dnStringInfoPtr->text[ i ];
					}
				textBuffer[ textIndex++ ] = ch;
				}

			/* Add the AVA to the DN */
			if( type == CRYPT_CERTINFO_COUNTRYNAME )
				{
				/* If it's a country code, force it to uppercase as per ISO 3166 */
				if( textIndex != 2 )
					return( CRYPT_ARGERROR_STR1 );
				textBuffer[ 0 ] = toUpper( textBuffer[ 0 ] );
				textBuffer[ 1 ] = toUpper( textBuffer[ 1 ] );
				status = insertDNstring( dnComponentListHead,
									type, textBuffer, 2,
									( dnStringInfoPtr->isContinued ) ? \
										DN_FLAG_CONTINUED | DN_FLAG_NOCHECK : \
										DN_FLAG_NOCHECK, NULL );
				}
			else
				status = insertDNstring( dnComponentListHead,
									type, textBuffer, textIndex,
									( dnStringInfoPtr->isContinued ) ? \
										DN_FLAG_CONTINUED | DN_FLAG_NOCHECK :
										DN_FLAG_NOCHECK, NULL );
			if( cryptStatusError( status ) )
				{
				deleteDN( dnComponentListHead );
				return( status );
				}

			/* Move on to the next AVA */
			isContinued = dnStringInfoPtr->isContinued;
			dnStringInfoPtr++;
			}
		while( isContinued );
		}
	while( --stringInfoIndex >= 0 );

	/* We're done, lock the DN against further updates */
	for( dnComponentPtr = *dnComponentListHead; dnComponentPtr != NULL;
		 dnComponentPtr = dnComponentPtr->next )
		dnComponentPtr->flags |= DN_FLAG_LOCKED;

	return( CRYPT_OK );
	}

/* Write a DN in string form */

int writeDNstring( STREAM *stream, const void *dnComponentListHead )
	{
	const DN_COMPONENT *dnComponentPtr = dnComponentListHead;

	if( dnComponentPtr == NULL )
		return( CRYPT_OK );

	assert( isReadPtr( dnComponentPtr, sizeof( DN_COMPONENT ) ) );

	/* Find the end of the DN string.  We have to print the RDNs backwards
	   because of ISODE's Janet memorial backwards encoding */
	while( dnComponentPtr->next != NULL )
		dnComponentPtr = dnComponentPtr->next;

	do
		{
		const DN_COMPONENT *dnComponentCursor;
		BOOLEAN isContinued;

		/* Find the start of the RDN */
		while( dnComponentPtr->prev != NULL && \
			   ( dnComponentPtr->prev->flags & DN_FLAG_CONTINUED ) )
			dnComponentPtr = dnComponentPtr->prev;
		dnComponentCursor = dnComponentPtr;
		dnComponentPtr = dnComponentPtr->prev;

		/* Print the current RDN */
		do
			{
			const DN_COMPONENT_INFO *componentInfoPtr = \
										dnComponentCursor->typeInfo;
			int i;

			/* Print the current AVA */
			swrite( stream, componentInfoPtr->name,
					strlen( componentInfoPtr->name ) );
			sputc( stream, '=' );
			for( i = 0; i < dnComponentCursor->valueLength; i++ )
				{
				const char ch = ( ( char * ) dnComponentCursor->value )[ i ];

				if( ch == ',' || ch == '=' || ch == '+' || ch == ';' || \
					ch == '\\' || ch == '"' )
					sputc( stream, '\\' );
				sputc( stream, ch );
				}

			/* If there are more AVAs in this RDN, print a continuation
			   indicator and move on to the next AVA */
			isContinued = dnComponentCursor->flags & DN_FLAG_CONTINUED;
			if( isContinued )
				{
				swrite( stream, " + ", 3 );
				dnComponentCursor = dnComponentCursor->next;
				}
			}
		while( isContinued );

		/* If there are more components to come, print an RDN separator */
		if( dnComponentPtr != NULL )
			swrite( stream, ", ", 2 );
		}
	while( dnComponentPtr != NULL && sStatusOK( stream ) );

	return( sGetStatus( stream ) );
	}
