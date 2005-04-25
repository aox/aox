/****************************************************************************
*																			*
*						Certificate Import/Export Routines					*
*						Copyright Peter Gutmann 1997-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#elif defined( INC_CHILD )
  #include "cert.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* Oddball OIDs that may be used to wrap certs */

#define OID_X509_USERCERTIFICATE	"\x06\x03\x55\x04\x24"

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Determine the object type and how long the total object is.  If fed an 
   unknown object from the external source we can (with some difficulty) 
   determine its type at runtime (although it's hardly LL(1)) and import it 
   as appropriate.  If fed an object by a cryptlib-internal function, the
   exact type will always be known.
   
   If the data starts with a [0], it's CMS attributes.  If it starts with a 
   sequence followed by an OID it's a cert chain/sequence or (rarely) a cert 
   wrapped up in some weird packaging.  If it starts with a sequence followed
   by an integer (version = 3), it's a PKCS #12 mess.  Otherwise, it follows 
   the general pattern SEQUENCE { tbsSomething, signature }, it's at this 
   point that distinguishing the different types gets tricky.

	Cert:			SEQUENCE { SEQUENCE {
						[0] EXPLICIT ... OPTIONAL,
							INTEGER,
							AlgorithmID,
							Name,
							SEQUENCE {			-- Validity
								{ UTCTime | GeneralizedTime }

	Attribute cert:	SEQUENCE { SEQUENCE {
							INTEGER OPTIONAL,
						[1]	Name,
							Name,
							AlgorithmID,
							INTEGER

	CRL:			SEQUENCE { SEQUENCE {
							INTEGER OPTIONAL,
							AlgorithmID,
							Name,
							{ UTCTime | GeneralizedTime }

	Cert request:	SEQUENCE { SEQUENCE {
							INTEGER,
							Name,
							SEQUENCE {			-- SubjectPublicKeyInfo
								AlgorithmID

	CRMF request:	SEQUENCE { SEQUENCE {
							INTEGER,
							SEQUENCE {
								{ [0] ... [9] }	-- cert request should have 
												-- [6] SubjectPublicKeyInfo

	CRMF rev.req:	SEQUENCE { SEQUENCE {
							{ [0] ... [9] }		-- Should have [1] INTEGER 
												-- (serialNo),

	OCSP request:	SEQUENCE { SEQUENCE {
						[0] EXPLICIT ... OPTIONAL,
						[1]	EXPLICIT ... OPTIONAL,
							SEQUENCE { SEQUENCE {
								{ SEQUENCE | [0] | [1] | [2] | [3] }
	
	OCSP resp:		SEQUENCE { SEQUENCE {
						[0] EXPLICIT ... OPTIONAL,
							{ [1] | [2] } ...,
							GeneralizedTime

	OCSP resp (cl):	SEQUENCE { SEQUENCE 
							{ SEQUENCE { SEQUENCE {
								OCTET STRING

	PKI user:		SEQUENCE { SEQUENCE {		-- Name
							{ SET ... | empty }	-- RDN or zero-length DN

   The first step is to strip out the SEQUENCE { SEQUENCE, which is shared 
   by all objects.  In addition we can remove the [0] ... OPTIONAL and
   [1] ... OPTIONAL, which isn't useful in distinguishing anything.  Since 
   the standard OCSP response can also have [2] in place of the [1] and 
   leaving it in isn't notably useful, we strip this as well.  Note that 
   attribute certs can be left in one of two states depending on whether 
   the initial INTEGER is present or not and PKI user info is also left in 
   one of two states depending on whether there's a DN present.  Rather than 
   parse down into the rest of the PKI user object (the next element is an 
   AlgorithmID that clashes with a cert and CRL), we use the presence of 
   a zero-length sequence to identify a PKI user object with an absent DN.  
   This leaves the following,

	Cert:					INTEGER,
							AlgorithmID,
							Name,
							SEQUENCE {			-- Validity
								{ UTCTime | GeneralizedTime }

	Attribute cert:			INTEGER OPTIONAL,
						[1]	Name,
							Name,					Name,
							AlgorithmID,			AlgorithmID,
							INTEGER					INTEGER

	CRL:					INTEGER OPTIONAL,
							AlgorithmID,
							Name,
							{ UTCTime | GeneralizedTime }

	Cert request:			INTEGER,
							Name,
							SEQUENCE {			-- SubjectPublicKeyInfo
								AlgorithmID

	CRMF request:			INTEGER,
							SEQUENCE {
								{ [0] ... [1] |	-- Implicitly tagged
								  [3] ... [9] }	-- [2] stripped

	CRMF rev.req:			{ [0] ... [1] |		-- Implicitly tagged
							  [3] ... [9] }		-- [2] stripped

	OCSP request:			SEQUENCE { SEQUENCE {
								{ SEQUENCE | [0] | [1] | [2] | [3] }
	
	OCSP resp:				GeneralizedTime

	OCSP resp (clib):		SEQUENCE { SEQUENCE {
								OCTET STRING

	PKI user:				SET ...				-- RDN

   Next we have the INTEGER, which also isn't notably useful.  Stripping this
   leaves:

	Cert:					AlgorithmID,
							Name,
							SEQUENCE {			-- Validity
								{ UTCTime | GeneralizedTime }

	Attribute cert:		[1]	Name,
							Name,					Name,
							AlgorithmID,			AlgorithmID,
							INTEGER					INTEGER

	CRL:					AlgorithmID,
							Name,
							{ UTCTime | GeneralizedTime }

	Cert request:			Name,
							SEQUENCE {			-- SubjectPublicKeyInfo
								AlgorithmID

	CRMF request:			SEQUENCE {
								{ [0] | [1] |	-- Primitive tag
								  [3] ... [9] }	-- [2] stripped

	CRMF rev.req:			{ [0] | [1] |		-- Primitive tag
							  [3] ... [9] }		-- [2] stripped

	OCSP request:			SEQUENCE { SEQUENCE {
								{ SEQUENCE | [0] | [1] | [2] | [3] }
	
	OCSP resp:				GeneralizedTime

	OCSP resp (clib):		SEQUENCE { SEQUENCE {
								OCTET STRING

	PKI user:				SET ...				-- RDN

   We can now immediately identify the first attribute cert variant by the 
   [1] ..., a CRMF revocation request by the not-stripped [0] or [1] 
   primitive tags (implicitly tagged INTEGER) or [3]...[9] ..., a standard 
   OCSP response by the GeneralizedTime, and the alternative PKI user 
   variant by the SET ..., leaving:

	Cert:					AlgorithmID,
							Name,
							SEQUENCE {			-- Validity
								{ UTCTime | GeneralizedTime }

	CRL:					AlgorithmID,
							Name,
							{ UTCTime | GeneralizedTime }

	Attribute cert:			Name,
							AlgorithmID,
							INTEGER

	Cert request:			Name,
							SEQUENCE {			-- SubjectPublicKeyInfo
								AlgorithmID

	CRMF request:			SEQUENCE {
								{ [3] ... [9] }

	OCSP request:			SEQUENCE { SEQUENCE {
								{ SEQUENCE | [0] | [1] | [2] | [3] }

	OCSP resp (clib):		SEQUENCE { SEQUENCE {
								OCTET STRING

   Expanding the complex types for cert, attribute cert, CRL, and cert 
   request, we get:

	Cert:					SEQUENCE {			-- AlgorithmID
								OBJECT IDENTIFIER,
								...
							Name,
							SEQUENCE {			-- Validity
								{ UTCTime | GeneralizedTime }

	CRL:					SEQUENCE {			-- AlgorithmID
								OBJECT IDENTIFIER,
								...
							Name,
							{ UTCTime | GeneralizedTime }

	Attribute cert:			SEQUENCE {			-- Name
								SET {
									...
								...
							SEQUENCE {			-- AlgorithmID
								OBJECT IDENTIFIER,
								...
							INTEGER

	Cert request:			SEQUENCE {			-- Name
								SET {
									...
								...
							SEQUENCE {			-- SubjectPublicKeyInfo
								AlgorithmID

	CRMF request:			SEQUENCE {
								{ [3] ... [9] }

	OCSP request:			SEQUENCE { SEQUENCE {
								{ SEQUENCE | [0] | [1] | [2] | [3] }

	OCSP resp (clib):		SEQUENCE { SEQUENCE {
								OCTET STRING

   Stripping the first SEQUENCE { we get:

	Cert:						OBJECT IDENTIFIER,
								...
							Name,
							SEQUENCE {			-- Validity
								{ UTCTime | GeneralizedTime }

	CRL:						OBJECT IDENTIFIER,
								...
							Name,
							{ UTCTime | GeneralizedTime }

	Attribute cert:				SET {
									...
								...
							SEQUENCE {			-- AlgorithmID
								OBJECT IDENTIFIER,
								...
							INTEGER

	Cert request:				SET {
									...
								...
							SEQUENCE {			-- SubjectPublicKeyInfo
								AlgorithmID

	CRMF request:				{ [3] ... [9] }

	OCSP request:			SEQUENCE {
								{ SEQUENCE | [0] | [1] | [2] | [3] }

	OCSP resp (clib):		SEQUENCE {
								OCTET STRING

   which allows us to distinguish certs and CRLs (the two are themselves
   distinguished by what follows the second Name) and cert requests and the 
   second attribute cert variant (the two are also distinguished by what
   follows the Name).  What's left now are the tricky ones, the other 
   request and response types:

	CRMF request:				{ [3] ... [9] }

	OCSP request:			SEQUENCE {
								{ SEQUENCE | [0] | [1] | [2] | [3] }

	OCSP resp (clib):		SEQUENCE {
								OCTET STRING

   which can themselves be distinguished by the remaining data */

static int decodeCertWrapper( STREAM *stream, int *offset )
	{
	BYTE oid[ MAX_OID_SIZE ];
	BOOLEAN isCertChain = FALSE;
	int oidLength, value, status;

	/* Read the contentType OID, determine the content type based on it,
	   and read the content encapsulation and header.  It can be either
	   a PKCS #7 cert chain, a Netscape cert sequence, or an X.509
	   userCertificate (which is just an oddball cert wrapper) */
	status = readRawObject( stream, oid, &oidLength, MAX_OID_SIZE, 
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	if( !memcmp( oid, OID_CMS_SIGNEDDATA, oidLength ) )
		isCertChain = TRUE;
	else
		if( !memcmp( oid, OID_X509_USERCERTIFICATE, oidLength ) )
			{
			/* Oddball wrapper type, set the payload offset to point to 
			   the certificate and indicate no wrapper present */
			*offset = stell( stream );
			status = readSequence( stream, NULL );
			return( cryptStatusError( status ) ? \
					status : CRYPT_CERTTYPE_NONE );
			}
		else
			if( memcmp( oid, OID_NS_CERTSEQ, oidLength ) )
				return( CRYPT_ERROR_BADDATA );
	readConstructedI( stream, NULL, 0 );
	status = readSequenceI( stream, NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a PKCS #7 certificate chain, burrow into the inner PKCS #7
	   content */
	if( isCertChain )
		{
		long integer;
		int innerLength;

		/* Read the version number (1 = PKCS #7 v1.5, 2 = PKCS #7 v1.6,
		   3 = S/MIME with attribute certificate(s)) and SET OF
		   DigestAlgorithmIdentifier (this is empty for a pure cert chain,
		   nonempty for signed data) */
		status = readShortInteger( stream, &integer );
		if( cryptStatusOK( status ) && ( integer < 1 || integer > 3 ) )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status ) )
			status = readSet( stream, &value );
		if( cryptStatusError( status ) )
			return( status );
		if( value > 0 )
			sSkip( stream, value );

		/* Read the ContentInfo header, contentType OID (ignored) and the 
		   inner content encapsulation.  Sometimes we may (incorrectly) get 
		   passed actual signed data (rather than degenerate zero-length 
		   data signifying a pure cert chain), if there's data present we 
		   skip it */
		readSequenceI( stream, &innerLength );
		status = readRawObject( stream, oid, &oidLength, MAX_OID_SIZE, 
								BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			return( status );
		if( innerLength == CRYPT_UNUSED )
			/* It's an indefinite-length ContentInfo, check for the EOC */
			checkEOC( stream );
		else
			/* If we've been fed signed data (i.e. the ContentInfo has the 
			   content field present), skip the content to get to the cert 
			   chain */
			if( innerLength > sizeofObject( oidLength ) )
				readUniversal( stream );
		readConstructed( stream, NULL, 0 );
		}

	/* We've finally reached the certificate(s), retry the read of the
	   certificate start */
	status = readSequence( stream, NULL );
	return( cryptStatusError( status ) ? status : CRYPT_CERTTYPE_CERTCHAIN );
	}

static int getCertObjectInfo( const void *object, const int objectTotalLength,
							  int *objectOffset, int *objectLength, 
							  CRYPT_CERTTYPE_TYPE *objectType,
							  const CERTFORMAT_TYPE formatType )
	{
	STREAM stream;
	BOOLEAN isContextTagged = FALSE, isLongData = FALSE;
	int tag, length, status;

	/* Set initial default values */
	*objectOffset = 0;
	*objectLength = CRYPT_ERROR;
	*objectType = CRYPT_CERTTYPE_NONE;

	/* If it's an SSL cert chain there's no recognisable tagging, however the
	   caller will have told us what it is */
	if( formatType == CRYPT_ICERTTYPE_SSL_CERTCHAIN )
		{
		*objectLength = objectTotalLength;
		*objectType = CRYPT_ICERTTYPE_SSL_CERTCHAIN;
		return( CRYPT_OK );
		}

	sMemConnect( &stream, object, objectTotalLength );

	/* Check that the start of the object is in order and get its length */
	if( peekTag( &stream ) == MAKE_CTAG( 0 ) || \
		formatType == CRYPT_ICERTTYPE_CMS_CERTSET )
		isContextTagged = TRUE;
	status = readConstructedI( &stream, &length, \
							   isContextTagged ? 0 : DEFAULT_TAG );
#if INT_MAX > 32767
	if( status == CRYPT_ERROR_OVERFLOW )
		{
		long longLength;

		/* CRLs can grow without bounds as more and more certs are 
		   accumulated, to handle these we have to fall back to an 
		   unconstrained read if a standard constrained read fails */
		sClearError( &stream );
		sseek( &stream, 0 );
		status = readLongSequence( &stream, &longLength );
		if( cryptStatusOK( status ) )
			{
			/* We don't have to check for the CRYPT_UNUSED indefinite-length
			   return value in this case since we can only get here if the
			   length overflows a 16-bit int, so it can never be indefinite-
			   length */
			length = ( int ) longLength;
			isLongData = TRUE;
			}
		}
	else
#endif /* Non-16-bit systems */
		if( cryptStatusOK( status ) && length == CRYPT_UNUSED )
			{
			/* It's a indefinite-length object, burrow into it to find it's
			   actual length */
			status = getObjectLength( object, objectTotalLength );
#if INT_MAX > 32767
			if( status == CRYPT_ERROR_OVERFLOW )
				status = getLongObjectLength( object, objectTotalLength );
#endif /* Non-16-bit systems */
			}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	*objectLength = ( length != CRYPT_UNUSED ) ? \
					( int ) sizeofObject( length ) : status;

	/* If the caller has specified that the data is in a fixed format, don't 
	   try and recognise any other format.  This prevents security holes of 
	   the type common in Windows software where data purportedly of type A 
	   is auto-recognised as harmful type B and processed as such after being
	   passed as type A by security-checking code */
	if( formatType != CRYPT_CERTTYPE_NONE )
		{
		sMemDisconnect( &stream );

		if( formatType > CRYPT_CERTTYPE_NONE && \
			formatType < CRYPT_CERTTYPE_LAST )
			*objectType = formatType;
		else
			switch( formatType )
				{
				case CERTFORMAT_DATAONLY:
					/* Standard certificate but created without creating a 
					   context for the accompanying public key */
					*objectType = CRYPT_CERTTYPE_CERTIFICATE;
					break;

				case CERTFORMAT_CTL:
					/* Cert chain used as a container for trusted certs, 
					   effectively a chain of CERTFORMAT_DATAONLY certs */
					*objectType = CRYPT_CERTTYPE_CERTCHAIN;
					break;

				case CERTFORMAT_REVINFO:
					/* Single CRL entry, treated as standard CRL with 
					   portions missing */
					*objectType = CRYPT_CERTTYPE_CRL;
					break;

				default:
					assert( NOTREACHED );
					return( CRYPT_ERROR_BADDATA );
				}
										
		return( isLongData ? CRYPT_ERROR_OVERFLOW : CRYPT_OK );
		}

	/* First we check for the easy ones, CMS attributes, which begin with a 
	   [0] IMPLICIT SET */
	if( isContextTagged )
		{
		*objectType = CRYPT_CERTTYPE_CMS_ATTRIBUTES;
		sMemDisconnect( &stream );
		return( isLongData ? CRYPT_ERROR_OVERFLOW : CRYPT_OK );
		}

	/* If it's a PKCS #7 certificate chain or Netscape cert.sequence,
	   there'll be an object identifier present.  Some sources also wrap
	   certs up in oddball OID's, so we check for these as well */
	if( peekTag( &stream ) == BER_OBJECT_IDENTIFIER )
		{
		status = decodeCertWrapper( &stream, objectOffset );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		*objectType = ( status != CRYPT_CERTTYPE_NONE ) ? \
					  status : CRYPT_CERTTYPE_CERTIFICATE;
		return( isLongData ? CRYPT_ERROR_OVERFLOW : CRYPT_OK );
		}

	/* If it's a PKCS #12 mess, there'll be a version number, 3, present */
	if( peekTag( &stream ) == BER_INTEGER )
		{
		long value;
		int offset;

		/* Strip off the amazing number of layers of bloat that PKCS #12 
		   lards a certificate with.  There are any number of different
		   interpretations of how to store certs in a PKCS #12 file, the
		   following is the one that (eventually) ends up in a cert that
		   we can read */
		status = readShortInteger( &stream, &value );
		if( cryptStatusError( status ) || value != 3 )
			{
			sMemDisconnect( &stream );
			return( CRYPT_ERROR_BADDATA );
			}
		readSequence( &stream, NULL );
		readFixedOID( &stream, OID_CMS_DATA );
		readConstructed( &stream, NULL, 0 );
		readOctetStringHole( &stream, NULL, DEFAULT_TAG );
		readSequence( &stream, NULL );
		readSequence( &stream, NULL );
		readFixedOID( &stream, OID_CMS_DATA );
		readConstructed( &stream, NULL, 0 );
		readOctetStringHole( &stream, NULL, DEFAULT_TAG );
		readSequence( &stream, NULL );
		readSequence( &stream, NULL );
		readFixedOID( &stream, 
					  MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x03" ) );
		readConstructed( &stream, NULL, 0 );
		readSequence( &stream, NULL );
		readFixedOID( &stream, 
					  MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x16\x01" ) );
		readConstructed( &stream, NULL, 0 );
		readOctetStringHole( &stream, &length, DEFAULT_TAG );
		offset = stell( &stream );	/* Certificate start */
		readSequence( &stream, NULL );
		status = readSequence( &stream, NULL );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		/* We've finally reached the cert, record its offset and length */
		*objectOffset = offset;
		*objectLength = length;
		*objectType = CRYPT_CERTTYPE_CERTIFICATE;
		return( isLongData ? CRYPT_ERROR_OVERFLOW : CRYPT_OK );
		}

	/* Read the inner sequence and skip optional tagged fields and the
	   INTEGER value */
	if( isLongData )
		{
		long longLength;

		status = readLongSequence( &stream, &longLength );
		if( cryptStatusOK( status ) )
			{
			/* If it's an (invalid) indefinite-length encoding we can't do 
			   anything with it */
			if( longLength == CRYPT_UNUSED )
				status = CRYPT_ERROR_BADDATA;
			else
				length = ( int ) longLength;
			}
		}
	else
		status = readSequence( &stream, &length );
	if( peekTag( &stream ) == MAKE_CTAG( 0 ) )
		readUniversal( &stream );
	if( peekTag( &stream ) == MAKE_CTAG( 1 ) )
		readUniversal( &stream );
	if( peekTag( &stream ) == MAKE_CTAG( 2 ) )
		readUniversal( &stream );
	if( peekTag( &stream ) == BER_INTEGER )
		readUniversal( &stream );
	if( cryptStatusOK( status ) )
		status = sGetStatus( &stream );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( length == 0 )
		{
		/* PKI user object with absent (non-specified) DN */
		sMemDisconnect( &stream );
		*objectType = CRYPT_CERTTYPE_PKIUSER;
		return( isLongData ? CRYPT_ERROR_OVERFLOW : CRYPT_OK );
		}

	/* If we've hit a [1] it's an attribute cert, if we've hit a
	   GeneralizedTime it's an OCSP response, if we've hit a SET it's PKI
	   user info, and if we've hit a [0] or [1] primitive tag (implicitly 
	   tagged INTEGER) or [3]...[9] it's a CRMF revocation request */
	tag = peekTag( &stream );
	if( tag == MAKE_CTAG( 1 ) || tag == BER_TIME_GENERALIZED || \
		tag == BER_SET )
		{
		sMemDisconnect( &stream );
		*objectType = \
			( tag == MAKE_CTAG( 1 ) ) ? CRYPT_CERTTYPE_ATTRIBUTE_CERT : \
			( tag == BER_TIME_GENERALIZED ) ? \
				CRYPT_CERTTYPE_OCSP_RESPONSE : CRYPT_CERTTYPE_PKIUSER;
		return( isLongData ? CRYPT_ERROR_OVERFLOW : CRYPT_OK );
		}
	if( tag == MAKE_CTAG_PRIMITIVE( 0 ) || \
		tag == MAKE_CTAG_PRIMITIVE( 1 ) || \
		( tag >= MAKE_CTAG( 3 ) && tag <= MAKE_CTAG( 9 ) ) )
		{
		sMemDisconnect( &stream );
		*objectType = CRYPT_CERTTYPE_REQUEST_REVOCATION;
		return( isLongData ? CRYPT_ERROR_OVERFLOW : CRYPT_OK );
		}

	/* Read the next SEQUENCE.  If it's followed by an OID, it's the 
	   AlgorithmIdentifier in a cert or CRL.  If it's followed by a SET, it's
	   the Name in a cert request or attribute cert.  If it's followed by a 
	   tag in the range [0]...[9] it's a horror from CRMF */
	status = readSequence( &stream, &length );
	if( cryptStatusOK( status ) && length <= 0 )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	tag = peekTag( &stream );
	if( tag == BER_OBJECT_IDENTIFIER )
		{
		/* Skip the AlgorithmIdentifier data and the following Name.  For a
		   cert we now have a SEQUENCE (from the Validity), for a CRL a
		   UTCTime or GeneralizedTime */
		sSkip( &stream, length );
		readUniversal( &stream );
		tag = readTag( &stream );
		sMemDisconnect( &stream );
		if( tag == BER_SEQUENCE )
			{
			*objectType = CRYPT_CERTTYPE_CERTIFICATE;
			return( isLongData ? CRYPT_ERROR_OVERFLOW : CRYPT_OK );
			}
		if( tag == BER_TIME_UTC || tag == BER_TIME_GENERALIZED )
			{
			*objectType = CRYPT_CERTTYPE_CRL;
			return( CRYPT_OK );
			}
		return( CRYPT_ERROR_BADDATA );
		}
	if( isLongData )
		/* Beyond this point we shouldn't be seeing long-length objects */
		return( CRYPT_ERROR_OVERFLOW );
	if( tag >= MAKE_CTAG( 0 ) && tag <= MAKE_CTAG( 9 ) )
		{
		/* Cert requests and revocation requests have the same format, 
		   however revocation requests should have the cert serial number 
		   present while cert requests shouldn't (at least in any normal
		   implementation), so we use this to distinguish the two.  If
		   this ever fails in the future, we can also look for things like
		   [6] (the public key) as a clue that it's a cert request */
		sMemDisconnect( &stream );
		*objectType = ( tag == MAKE_CTAG( 1 ) ) ? \
				CRYPT_CERTTYPE_REQUEST_REVOCATION : CRYPT_CERTTYPE_REQUEST_CERT;
		return( CRYPT_OK );
		}
	if( tag == BER_SET )
		{
		sSkip( &stream, length );
		readSequence( &stream, NULL );
		tag = readTag( &stream );
		sMemDisconnect( &stream );
		if( tag == BER_OBJECT_IDENTIFIER )
			{
			*objectType = CRYPT_CERTTYPE_ATTRIBUTE_CERT;
			return( CRYPT_OK );
			}
		if( tag == BER_SEQUENCE )
			{
			*objectType = CRYPT_CERTTYPE_CERTREQUEST;
			return( CRYPT_OK );
			}
		return( CRYPT_ERROR_BADDATA );
		}

	/* Read the next SEQUENCE.  If it's followed by a yet another SEQUENCE 
	   or a tag from [0] ... [3] it's an OCSP request, if it's followed by
	   an OCTET STRING it's a cryptlib OCSP response */
	readSequence( &stream, NULL );
	tag = readTag( &stream );
	sMemDisconnect( &stream );
	if( tag == BER_SEQUENCE || \
		( tag >= MAKE_CTAG( 0 ) && tag <= MAKE_CTAG( 3 ) ) )
		{
		*objectType = CRYPT_CERTTYPE_OCSP_REQUEST;
		return( CRYPT_OK );
		}
	if( tag == BER_OCTETSTRING )
		{
		*objectType = CRYPT_CERTTYPE_OCSP_RESPONSE;
		return( CRYPT_OK );
		}

	/* It's nothing identifiable */
	return( CRYPT_ERROR_BADDATA );
	}

/****************************************************************************
*																			*
*								Import/Export Functions						*
*																			*
****************************************************************************/

/* Import a certificate object.  If the import type is set to create a data-
   only cert, its publicKeyInfo pointer is set to the start of the encoded 
   public key to allow it to be decoded later.  Returns the length of the 
   certificate */

int importCert( const void *certObject, const int certObjectLength,
				CRYPT_CERTIFICATE *certificate,
				const CRYPT_USER cryptOwner,
				const CRYPT_KEYID_TYPE keyIDtype,
				const void *keyID, const int keyIDlength,
				const CERTFORMAT_TYPE formatType )
	{
	CERT_INFO *certInfoPtr;
	CRYPT_CERTTYPE_TYPE type;
	STREAM stream;
	BOOLEAN isDecodedObject = FALSE;
	int ( *readCertObjectFunction )( STREAM *stream, CERT_INFO *certInfoPtr );
	void *certObjectPtr = ( void * ) certObject, *certBuffer;
	int objectLength = certObjectLength, length, offset = 0;
	int complianceLevel, initStatus = CRYPT_OK, i, status;

	*certificate = CRYPT_ERROR;

	/* Determine how much checking we need to perform */
	status = krnlSendMessage( cryptOwner, IMESSAGE_GETATTRIBUTE, 
							  &complianceLevel, 
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's not a pre-specified or special-case format, check whether it's 
	   some form of encoded certificate object */
	if( formatType == CRYPT_CERTTYPE_NONE )
		{
		const CRYPT_CERTFORMAT_TYPE format = \
				base64checkHeader( certObject, certObjectLength, &offset );

		if( format == CRYPT_ICERTFORMAT_SMIME_CERTIFICATE || \
			format == CRYPT_CERTFORMAT_TEXT_CERTIFICATE )
			{
			const char *certObjectDataPtr = \
								( const char * ) certObject + offset;
			int decodedLength;

			/* It's base64/PEM/SMIME-encoded, decode it into a temporary 
			   buffer */
			decodedLength = base64decodeLen( certObjectDataPtr, 
											 certObjectLength );
			if( decodedLength <= 128 || decodedLength > 8192 )
				return( CRYPT_ERROR_BADDATA );
			if( ( certObjectPtr = clAlloc( "importCert",
										   decodedLength ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			status = base64decode( certObjectPtr, decodedLength, 
								   certObjectDataPtr, certObjectLength, 
								   format );
			if( cryptStatusError( status ) )
				{
				clFree( "importCert", certObjectPtr );
				return( status );
				}
			isDecodedObject = TRUE;
			objectLength = decodedLength;
			}
		else
			/* If it's binary-encoded MIME data, we don't need to decode it 
			   but still need to skip the MIME header */
			if( format == CRYPT_CERTFORMAT_CERTIFICATE || \
				format == CRYPT_CERTFORMAT_CERTCHAIN )
				{
				assert( offset > 0 );

				certObjectPtr = ( BYTE * ) certObject + offset;
				objectLength -= offset;
				}
		}

	/* Determine the object's type and length and check the encoding unless
	   we're running in oblivious mode */
	status = getCertObjectInfo( certObjectPtr, objectLength, &offset, 
								&length, &type, formatType );
	if( cryptStatusOK( status ) && \
		complianceLevel > CRYPT_COMPLIANCELEVEL_OBLIVIOUS && \
		formatType != CRYPT_ICERTTYPE_SSL_CERTCHAIN )
		status = checkObjectEncoding( ( BYTE * ) certObjectPtr + offset, 
									  length );
	if( cryptStatusError( status ) )
		{
		if( isDecodedObject )
			clFree( "importCert", certObjectPtr );
		return( status );
		}
	status = CRYPT_OK;	/* checkEncoding() returns a length */

	/* If it's a cert chain, this is handled specially since we need to
	   import a plurality of certs at once */
	if( type == CRYPT_CERTTYPE_CERTCHAIN || \
		type == CRYPT_ICERTTYPE_CMS_CERTSET || \
		type == CRYPT_ICERTTYPE_SSL_CERTCHAIN )
		{
		/* Read the cert chain into a collection of internal cert objects
		   This returns a handle to the leaf cert in the chain, with the
		   remaining certs being accessible within it via the cert cursor
		   functions.  Because the different chain types are only used to
		   distinguish the chain wrapper type on import, the final object
		   type which is created is always a CRYPT_CERTTYPE_CERTCHAIN no
		   matter what the import format was */
		sMemConnect( &stream, ( BYTE * ) certObjectPtr + offset, length );
		if( type == CRYPT_CERTTYPE_CERTCHAIN )
			readSequence( &stream, NULL );	/* Skip the outer wrapper */
		status = readCertChain( &stream, certificate, cryptOwner, type, 
								keyIDtype, keyID, keyIDlength, 
								( formatType == CERTFORMAT_DATAONLY ||
								  formatType == CERTFORMAT_CTL ) ? \
									TRUE : FALSE );
		sMemDisconnect( &stream );
		if( isDecodedObject )
			clFree( "importCert", certObjectPtr );
		return( status );
		}

	assert( keyIDtype == CRYPT_KEYID_NONE && keyID == NULL && \
			keyIDlength == 0 );

	/* Select the function to use to read the certificate object */
	for( i = 0; certReadTable[ i ].type != type && \
				certReadTable[ i ].type != CRYPT_CERTTYPE_NONE; i++ );
	if( certReadTable[ i ].type == CRYPT_CERTTYPE_NONE || \
		certReadTable[ i ].readFunction == NULL )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	readCertObjectFunction = certReadTable[ i ].readFunction;

	/* Allocate a buffer to store a copy of the object so we can preserve the
	   original for when it's needed again later, and try and create the
	   certificate object.  All the objects (including the CMS attributes,
	   that in theory aren't needed for anything further) need to be kept
	   around in their encoded form, which is often incorrect and therefore
	   can't be reconstructed from the decoded info.  The readXXX() functions 
	   record pointers to the required encoded fields so they can be 
	   recovered later in their (possibly incorrect) form, and these pointers 
	   need to be to a persistent copy of the encoded object.  In addition the 
	   cert objects need to be kept around anyway for sig checks and possible 
	   re-export */
	if( ( certBuffer = clAlloc( "importCert", length ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	else
		/* Create the certificate object */
		status = createCertificateInfo( &certInfoPtr, cryptOwner, type );
	if( cryptStatusError( status ) )
		{
		if( isDecodedObject )
			clFree( "importCert", certObjectPtr );
		clFree( "importCert", certBuffer );
		return( status );
		}
	*certificate = status;

	/* If we're doing a deferred read of the public key components (they'll
	   be decoded later when we know whether we need them), set the data-only
	   flag to ensure we don't try to decode them */
	if( formatType == CERTFORMAT_DATAONLY || formatType == CERTFORMAT_CTL )
		certInfoPtr->flags |= CERT_FLAG_DATAONLY;

	/* If we're reading a single entry from a CRL, indicate that the 
	   resulting object is a standalone single CRL entry rather than a proper
	   CRL */
	if( formatType == CERTFORMAT_REVINFO )
		certInfoPtr->flags |= CERT_FLAG_CRLENTRY;

	/* Copy in the certificate object for later use */
	memcpy( certBuffer, ( BYTE * ) certObjectPtr + offset, length );
	certInfoPtr->certificate = certBuffer;
	certInfoPtr->certificateSize = length;

	/* Parse the object into the certificate.  Note that we have to use the
	   copy in the certBuffer rather than the original since the readXXX()
	   functions record pointers to various encoded fields */
	sMemConnect( &stream, certBuffer, length );
	if( type != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
		type != CRYPT_CERTTYPE_RTCS_REQUEST && \
		type != CRYPT_CERTTYPE_RTCS_RESPONSE )
		/* Skip the outer wrapper */
		readLongSequence( &stream, NULL );
	status = readCertObjectFunction( &stream, certInfoPtr );
	sMemDisconnect( &stream );
	if( isDecodedObject )
		clFree( "importCert", certObjectPtr );
	if( cryptStatusError( status ) )
		{
		/* The import failed, make sure that the object gets destroyed when 
		   we notify the kernel that the setup process is complete.  We also
		   have to explicitly destroy the attached context since at this
		   point it hasn't been associated with the certificate yet, so it
		   won't be automatically destroyed by the kernel when the cert is 
		   destroyed */
		krnlSendNotifier( *certificate, IMESSAGE_DESTROY );
		if( certInfoPtr->iPubkeyContext != CRYPT_ERROR )
			{
			krnlSendNotifier( certInfoPtr->iPubkeyContext, 
							  IMESSAGE_DECREFCOUNT );
			certInfoPtr->iPubkeyContext = CRYPT_ERROR;
			}
		initStatus = status;
		}

	/* We've finished setting up the object-type-specific info, tell the 
	   kernel that the object is ready for use */
	status = krnlSendMessage( *certificate, IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		{
		*certificate = CRYPT_ERROR;
		return( cryptStatusError( initStatus ) ? initStatus : status );
		}

	/* If this is a type of object that has a public key associated with it, 
	   notify the kernel that the given context is attached to the cert.  
	   Note that we can only do this at this point because the cert object
	   can't receive general messages until its status is set to OK.  In 
	   addition since this is an internal object used only by the cert we 
	   tell the kernel not to increment its reference count when it attaches
	   it to the cert object.  Finally, we're ready to go so we mark the 
	   object as initialised (we can't do this before the initialisation is 
	   complete because the kernel won't forward the message to a not-ready-
	   for-use object)*/
	if( certInfoPtr->iPubkeyContext != CRYPT_ERROR )
		krnlSendMessage( *certificate, IMESSAGE_SETDEPENDENT,
						 &certInfoPtr->iPubkeyContext, 
						 SETDEP_OPTION_NOINCREF );
	return( krnlSendMessage( *certificate, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_UNUSED, 
							 CRYPT_IATTRIBUTE_INITIALISED ) );
	}

/* Export a certificate/certification request.  This just writes the
   internal encoded object to an external buffer.  For cert/cert chain export
   the possibilities are as follows:

						Export
	Type  |		Cert				Chain
	------+--------------------+---------------
	Cert  | Cert			   | Cert as chain
		  |					   |
	Chain | Currently selected | Chain
		  | cert in chain	   |					*/

int exportCert( void *certObject, int *certObjectLength,
				const CRYPT_CERTFORMAT_TYPE certFormatType,
				const CERT_INFO *certInfoPtr, const int maxLength )
	{
	const CRYPT_CERTFORMAT_TYPE baseFormatType = \
		( certFormatType == CRYPT_CERTFORMAT_TEXT_CERTIFICATE || \
		  certFormatType == CRYPT_CERTFORMAT_XML_CERTIFICATE ) ? \
			CRYPT_CERTFORMAT_CERTIFICATE : \
		( certFormatType == CRYPT_CERTFORMAT_TEXT_CERTCHAIN || \
		  certFormatType == CRYPT_CERTFORMAT_XML_CERTCHAIN ) ? \
			CRYPT_CERTFORMAT_CERTCHAIN : \
			certFormatType;
	STREAM stream;
	void *buffer;
	int length, encodedLength, status;

	/* If it's an internal format, write it and exit */
	if( certFormatType == CRYPT_ICERTFORMAT_CERTSET || \
		certFormatType == CRYPT_ICERTFORMAT_CERTSEQUENCE || \
		certFormatType == CRYPT_ICERTFORMAT_SSL_CERTCHAIN )
		{
		*certObjectLength = ( int ) \
				sizeofCertCollection( certInfoPtr, certFormatType );
		if( certObject == NULL )
			return( CRYPT_OK );
		if( *certObjectLength > maxLength )
			return( CRYPT_ERROR_OVERFLOW );
		sMemOpen( &stream, certObject, *certObjectLength );
		status = writeCertCollection( &stream, certInfoPtr,
									  certFormatType );
		sMemDisconnect( &stream );
		return( status );
		}

	/* Determine how big the output object will be */
	if( baseFormatType == CRYPT_CERTFORMAT_CERTCHAIN )
		{
		STREAM nullStream;

		assert( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
				certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );

		sMemOpen( &nullStream, NULL, 0 );
		status = writeCertChain( &nullStream, certInfoPtr );
		length = stell( &nullStream );
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		length = certInfoPtr->certificateSize;
	encodedLength = ( baseFormatType != certFormatType ) ? \
					base64encodeLen( length, certInfoPtr->type ) : length;

	/* Set up the length information */
	*certObjectLength = encodedLength;
	if( certObject == NULL )
		return( CRYPT_OK );
	if( encodedLength > maxLength )
		return( CRYPT_ERROR_OVERFLOW );
	if( !isWritePtr( certObject, encodedLength ) )
		return( CRYPT_ARGERROR_STR1 );

	/* If it's a simple object, write either the DER-encoded object or its
	   base64 / S/MIME-encoded form directly to the output */
	if( certFormatType == CRYPT_CERTFORMAT_CERTIFICATE || \
		certFormatType == CRYPT_ICERTFORMAT_DATA )
		{
		memcpy( certObject, certInfoPtr->certificate, length );
		return( CRYPT_OK );
		}
	if( certFormatType == CRYPT_CERTFORMAT_TEXT_CERTIFICATE || \
		certFormatType == CRYPT_CERTFORMAT_XML_CERTIFICATE )
		{
		status = base64encode( certObject, maxLength, 
							   certInfoPtr->certificate,
							   certInfoPtr->certificateSize, 
							   certInfoPtr->type );
		if( !cryptStatusError( status ) )
			{
			/* The base64encodeLen() value is only a worst-case estimate
			   since we can't determine the exact size without doing the
			   actual encoding, so we update the actual length value once
			   we've done the encoding in case it's changed */
			*certObjectLength = status;
			status = CRYPT_OK;
			}
		return( status );
		}

	/* It's a straight cert chain, write it directly to the output */
	if( certFormatType == CRYPT_CERTFORMAT_CERTCHAIN )
		{
		sMemOpen( &stream, certObject, length );
		status = writeCertChain( &stream, certInfoPtr );
		sMemDisconnect( &stream );
		return( status );
		}

	/* It's a base64 / S/MIME-encoded cert chain, write it to a temporary
	   buffer and then encode it to the output */
	assert( certFormatType == CRYPT_CERTFORMAT_TEXT_CERTCHAIN || \
			certFormatType == CRYPT_CERTFORMAT_XML_CERTCHAIN );
	if( ( buffer = clAlloc( "exportCert", length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	sMemOpen( &stream, buffer, length );
	status = writeCertChain( &stream, certInfoPtr );
	if( cryptStatusOK( status ) )
		{
		status = base64encode( certObject, maxLength, buffer, length, 
							   CRYPT_CERTTYPE_CERTCHAIN );
		if( !cryptStatusError( status ) )
			{
			/* The base64encodeLen() value is only a worst-case estimate
			   since we can't determine the exact size without doing the
			   actual encoding, so we update the actual length value once
			   we've done the encoding in case it's changed */
			*certObjectLength = status;
			status = CRYPT_OK;
			}
		}
	sMemClose( &stream );
	clFree( "exportCert", buffer );

	return( status );
	}
