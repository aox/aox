/****************************************************************************
*																			*
*							Certificate Read Routines						*
*						Copyright Peter Gutmann 1996-2003					*
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

/* Prototypes for functions in certext.c */

int fixAttributes( CERT_INFO *certInfoPtr );

/****************************************************************************
*																			*
*							Read Certificate Components						*
*																			*
****************************************************************************/

/* Return from a cert info read after encountering an error, setting the 
   extended error information if the error was caused by invalid data.  
   Although this isn't actually returned to the caller because the cert
   object isn't created, it allows more precise error diagnosis for other 
   routines */

static int certErrorReturn( CERT_INFO *certInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE errorLocus,
							const int status )
	{
	if( status == CRYPT_ERROR_BADDATA || status == CRYPT_ERROR_UNDERFLOW )
		setErrorInfo( certInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_VALUE );
	return( status );
	}

/* Read a certificate serial number */

static int readSerialNumber( STREAM *stream, CERT_INFO *certInfoPtr, 
							 const int tag )
	{
	BYTE integer[ MAX_SERIALNO_SIZE ];
	int integerLength, status;

	/* Read the integer component of the serial number */
	status = readIntegerTag( stream, integer, &integerLength, 
							 MAX_SERIALNO_SIZE, tag );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SERIALNUMBER,
								 status ) );

	/* Some certs may have a serial number of zero, which is turned into a
	   zero-length integer by the ASN.1 read code which truncates leading
	   zeroes that are added due to ASN.1 encoding requirements.  If we get 
	   a zero-length integer, we turn it into a single zero byte */
	if( !integerLength )
		{
		integerLength++;
		integer[ 0 ] = 0;
		}

	/* Copy the data across for the caller */
	return( setSerialNumber( certInfoPtr, integer, integerLength ) );
	}

/* Read validity information.  We allow for GeneralizedTime encodings as
   well since these are used in some broken certs */

static int readValidity( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int status;

	readSequence( stream, NULL );
	if( peekTag( stream ) == BER_TIME_UTC )
		status = readUTCTime( stream, &certInfoPtr->startTime );
	else
		status = readGeneralizedTime( stream, &certInfoPtr->startTime );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_VALIDFROM,
								 status ) );
	if( peekTag( stream ) == BER_TIME_UTC )
		status = readUTCTime( stream, &certInfoPtr->endTime );
	else
		status = readGeneralizedTime( stream, &certInfoPtr->endTime );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_VALIDTO,
								 status ) );
	return( CRYPT_OK );
	}

static int readCrmfValidity( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int tag, status;

	status = readConstructed( stream, NULL, CTAG_CF_VALIDITY );
	tag = peekTag( stream );
	if( tag == MAKE_CTAG( 0 ) )
		{
		readConstructed( stream, NULL, 0 );
		if( peekTag( stream ) == BER_TIME_UTC )
			status = readUTCTime( stream, &certInfoPtr->startTime );
		else
			status = readGeneralizedTime( stream, &certInfoPtr->startTime );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_VALIDFROM,
									 status ) );
		tag = peekTag( stream );
		}
	if( tag == MAKE_CTAG( 1 ) )
		{
		readConstructed( stream, NULL, 1 );
		if( peekTag( stream ) == BER_TIME_UTC )
			status = readUTCTime( stream, &certInfoPtr->endTime );
		else
			status = readGeneralizedTime( stream, &certInfoPtr->endTime );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_VALIDTO,
									 status ) );
		}
	return( status );
	}

/* Read a uniqueID */

static int readUniqueID( STREAM *stream, CERT_INFO *certInfoPtr,
						 const CRYPT_ATTRIBUTE_TYPE type )
	{
	int length, status;

	/* Read the length of the unique ID, allocate room for it, and read it
	   into the cert.  We ignore the tag since we've already checked it via
	   peekTag() before we got here */
	status = readBitStringHole( stream, &length, ANY_TAG );
	if( cryptStatusOK( status ) && ( length < 1 || length > 1024 ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		{
		void *bufPtr;

		if( ( bufPtr = clDynAlloc( "readUniqueID", length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		if( type == CRYPT_CERTINFO_SUBJECTUNIQUEID )
			{
			certInfoPtr->cCertCert->subjectUniqueID = bufPtr;
			certInfoPtr->cCertCert->subjectUniqueIDlength = length;
			}
		else
			{
			certInfoPtr->cCertCert->issuerUniqueID = bufPtr;
			certInfoPtr->cCertCert->issuerUniqueIDlength = length;
			}
		status = sread( stream, bufPtr, length );
		}
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, type, status ) );
	return( CRYPT_OK );
	}

/* Read DN information and remember the encoded DN data so we can copy it 
   (complete with any encoding errors) to the issuer DN field of anything
   we sign */

static int readSubjectDN( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int status;

	certInfoPtr->subjectDNptr = sMemBufPtr( stream );
	certInfoPtr->subjectDNsize = stell( stream );
	status = readDN( stream, &certInfoPtr->subjectName );
	certInfoPtr->subjectDNsize = stell( stream ) - certInfoPtr->subjectDNsize;
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
								 status ) );
	return( CRYPT_OK );
	}

static int readIssuerDN( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int status;

	certInfoPtr->issuerDNptr = sMemBufPtr( stream );
	certInfoPtr->issuerDNsize = stell( stream );
	status = readDN( stream, &certInfoPtr->issuerName );
	certInfoPtr->issuerDNsize = stell( stream ) - certInfoPtr->issuerDNsize;
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
								 status ) );
	return( CRYPT_OK );
	}

/* Read public-key information */

static int readPublicKeyInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int status;

	certInfoPtr->publicKeyInfo = sMemBufPtr( stream );
	certInfoPtr->publicKeyInfoSize = getStreamObjectLength( stream );
	if( certInfoPtr->flags & CERT_FLAG_DATAONLY )
		{
		/* We're doing deferred handling of the public key, skip it for now.
		   Because of weird tagging in things like CRMF objects we have to
		   read the information as a generic hole rather than a normal
		   SEQUENCE.  In addition because readAlgoID() can return non-stream
		   errors (for example an algorithm not-available status) we have to
		   explicitly check the return status rather than relying on it to 
		   be carried along in the stream state */
		readGenericHole( stream, NULL, DEFAULT_TAG );
		status = readAlgoID( stream, &certInfoPtr->publicKeyAlgo );
		if( cryptStatusOK( status ) )
			status = readUniversal( stream );
		}
	else
		{
		status = iCryptReadSubjectPublicKey( stream, 
									&certInfoPtr->iPubkeyContext, FALSE );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( certInfoPtr->iPubkeyContext, 
									  IMESSAGE_GETATTRIBUTE, 
									  &certInfoPtr->publicKeyAlgo, 
									  CRYPT_CTXINFO_ALGO );
		}
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, 
								 CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, 
								 status ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read a Certificate Object						*
*																			*
****************************************************************************/

/* Read the information in a certificate */

static int readCertInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int length, endPos, status;

	/* Read the outer SEQUENCE and version number if it's present */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;
	if( peekTag( stream ) == MAKE_CTAG( CTAG_CE_VERSION ) )
		{
		long version;

		readConstructed( stream, NULL, CTAG_CE_VERSION );
		readShortInteger( stream, &version );
		certInfoPtr->version = version + 1;	/* Zero-based */
		}
	else
		certInfoPtr->version = 1;

	/* Read the serial number */
	status = readSerialNumber( stream, certInfoPtr, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	/* Skip the signature algorithm information.  This was included to avert
	   a somewhat obscure attack that isn't possible anyway because of the
	   way the signature data is encoded in PKCS #1 sigs (although it's still
	   possible for some of the ISO sig.types) so there's no need to record
	   it */
	readUniversal( stream );

	/* Read the issuer name, validity information, and subject name */
	status = readIssuerDN( stream, certInfoPtr );
	if( cryptStatusOK( status ) )
		status = readValidity( stream, certInfoPtr );
	if( cryptStatusOK( status ) )
		status = readSubjectDN( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Check to see whether it's a self-signed cert */
	if( certInfoPtr->issuerDNsize == certInfoPtr->subjectDNsize && \
		!memcmp( certInfoPtr->issuerDNptr, certInfoPtr->subjectDNptr,
				 certInfoPtr->subjectDNsize ) )
		certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;

	/* Read the public key information */
	status = readPublicKeyInfo( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the issuer and subject unique ID's if there are any present */
	if( peekTag( stream ) == MAKE_CTAG_PRIMITIVE( CTAG_CE_ISSUERUNIQUEID ) )
		{
		status = readUniqueID( stream, certInfoPtr, 
							   CRYPT_CERTINFO_ISSUERUNIQUEID );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( peekTag( stream ) == MAKE_CTAG_PRIMITIVE( CTAG_CE_SUBJECTUNIQUEID ) )
		{
		status = readUniqueID( stream, certInfoPtr, 
							   CRYPT_CERTINFO_SUBJECTUNIQUEID );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the extensions if there are any present.  Because some certs will
	   have broken encoding of lengths, we allow for a bit of slop for
	   software that gets the length encoding wrong by a few bytes */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_CERTIFICATE, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	/* Fix up any problems in attributes */
	if( cryptStatusOK( status ) )
		status = fixAttributes( certInfoPtr );

	return( status );
	}

/* Read the information in an attribute certificate */

static int readAttributeCertInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int length, endPos, status;

	/* Read the outer SEQUENCE and version number */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;
	if( peekTag( stream ) == BER_INTEGER )
		{
		long version;

		readShortInteger( stream, &version );
		certInfoPtr->version = version + 1;	/* Zero-based */
		}
	else
		certInfoPtr->version = 1;

	/* Read the subject and issuer names */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_AC_BASECERTIFICATEID ) )
		{
		/* !!!!!!!!!!!! */
		return( CRYPT_ERROR );	/* Not handled yet */
		}
	if( peekTag( stream ) == MAKE_CTAG( CTAG_AC_ENTITYNAME ) )
		{
		readConstructed( stream, NULL, CTAG_AC_ENTITYNAME );
		status = readSubjectDN( stream, certInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = readIssuerDN( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Skip the signature algorithm information.  This was included to avert
	   a somewhat obscure attack that isn't possible anyway because of the
	   way the signature data is encoded in PKCS #1 sigs (although it's still
	   possible for some of the ISO sig.types) so there's no need to record
	   it */
	readUniversal( stream );

	/* Read the serial number and validity information */
	status = readSerialNumber( stream, certInfoPtr, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = readValidity( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Skip the attributes for now since these aren't really defined yet */
	readUniversal( stream );

	/* Read the issuer unique ID if there's one present */
	if( peekTag( stream ) == BER_BITSTRING )
		{
		status = readUniqueID( stream, certInfoPtr, 
							   CRYPT_CERTINFO_ISSUERUNIQUEID );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the extensions if there are any present.  Because some certs will
	   have broken encoding of lengths, we allow for a bit of slop for
	   software that gets the length encoding wrong by a few bytes */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_ATTRIBUTE_CERT, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	return( status );
	}

/* Read the information in a CRL.  We read various lengths as long values 
   since CRLs can get quite large */

static int readCRLInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;
	long length, endPos;
	int status;

	/* If it's a standalone CRL entry, read the single entry and return */
	if( certInfoPtr->flags & CERT_FLAG_CRLENTRY )
		return( readCRLentry( stream, &certRevInfo->revocations, 
							  &certInfoPtr->errorLocus, 
							  &certInfoPtr->errorType ) );

	/* Read the outer SEQUENCE and version number if it's present */
	status = readLongSequence( stream, &length );
	if( cryptStatusOK( status ) && length == CRYPT_UNUSED )
		/* If it's an (invalid) indefinite-length encoding we can't do 
		   anything with it */
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	if( peekTag( stream ) == BER_INTEGER )
		{
		long version;

		readShortInteger( stream, &version );
		certInfoPtr->version = version + 1;	/* Zero-based */
		}
	else	
		certInfoPtr->version = 1;

	/* Skip the signature algorithm information.  This was included to avert
	   a somewhat obscure attack that isn't possible anyway because of the
	   way the signature data is encoded in PKCS #1 sigs (although it's still
	   possible for some of the ISO sig.types) so there's no need to record
	   it */
	readUniversal( stream );

	/* Read the issuer name, update time, and optional next update time */
	status = readIssuerDN( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	status = readUTCTime( stream, &certInfoPtr->startTime );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_THISUPDATE,
								 status ) );
	if( peekTag( stream ) == BER_TIME_UTC )
		{
		status = readUTCTime( stream, &certInfoPtr->endTime );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_NEXTUPDATE,
									 status ) );
		}

	/* Read the SEQUENCE OF revoked certs and make the currently selected one
	   the start of the list */
	if( stell( stream ) < endPos - MIN_ATTRIBUTE_SIZE && \
		peekTag( stream ) == BER_SEQUENCE )
		{
		status = readLongSequence( stream, &length );
		if( cryptStatusOK( status ) && length == CRYPT_UNUSED )
			/* If it's an (invalid) indefinite-length encoding we can't do 
			   anything with it */
			status = CRYPT_ERROR_BADDATA;
		while( cryptStatusOK( status ) && length > MIN_ATTRIBUTE_SIZE )
			{
			const long innerStartPos = stell( stream );

			status = readCRLentry( stream, &certRevInfo->revocations, 
								   &certInfoPtr->errorLocus, 
								   &certInfoPtr->errorType );
			length -= stell( stream ) - innerStartPos;
			}
		if( cryptStatusError( status ) )
			/* The invalid attribute isn't quite a user certificate, but 
			   it's the data that arose from a user certificate so it's the 
			   most appropriate locus for the error */
			return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE, 
									 status ) );
		certRevInfo->currentRevocation = certRevInfo->revocations;
		}

	/* Read the extensions if there are any present.  Because some CRL's will
	   have broken encoding of lengths, we allow for a bit of slop for
	   software that gets the length encoding wrong by a few bytes */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_CRL, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	/* Fix up any problems in attributes */
	if( cryptStatusOK( status ) )
		status = fixAttributes( certInfoPtr );

	return( status );
	}

/* Read CMS attributes */

static int readCmsAttributes( STREAM *stream, CERT_INFO *attributeInfoPtr )
	{
	/* CMS attributes are straight attribute objects so we just pass the call
	   through */
	return( readAttributes( stream, &attributeInfoPtr->attributes,
							CRYPT_CERTTYPE_CMS_ATTRIBUTES, CRYPT_UNUSED,
							&attributeInfoPtr->errorLocus,
							&attributeInfoPtr->errorType ) );
	}

/* Read the information in a certification request */

static int readCertRequestInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	long version;
	int status;

	/* Skip the outer SEQUENCE and read the version number */
	readSequence( stream, NULL );
	readShortInteger( stream, &version );
	certInfoPtr->version = version + 1;	/* Zero-based */

	/* Read the subject name and public key information */
	status = readSubjectDN( stream, certInfoPtr );
	if( cryptStatusOK( status ) )
		status = readPublicKeyInfo( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the attributes */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_CR_ATTRIBUTES ) )
		{
		int length;
		
		status = readConstructed( stream, &length, CTAG_CR_ATTRIBUTES );
		if( cryptStatusOK( status ) && length >= MIN_ATTRIBUTE_SIZE )
			status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_CERTREQUEST, length, 
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		}

	/* Fix up any problems in attributes */
	if( cryptStatusOK( status ) )
		status = fixAttributes( certInfoPtr );

	/* Certification requests are always self-signed */
	certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
	return( status );
	}

/* Read the information in a CRMF certificate request.  We enforce the
   requirement that the request must contain at least a subject DN and a
   public key */

static int readCrmfRequestInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int tag, status;

	/* Skip the outer SEQUENCE, request ID, and inner SEQUENCE */
	readSequence( stream, NULL );
	readUniversal( stream );
	status = readSequence( stream, NULL );

	/* Skip any junk before the Validity, SubjectName, or 
	   SubjectPublicKeyInfo (the semantics of what we're stripping are at 
	   best undefined (version), at worst dangerous (serialNumber) */
	while( cryptStatusOK( status ) && \
		   ( peekTag( stream ) != MAKE_CTAG( CTAG_CF_VALIDITY ) && \
		     peekTag( stream ) != MAKE_CTAG( CTAG_CF_SUBJECT ) && \
			 peekTag( stream ) != MAKE_CTAG( CTAG_CF_PUBLICKEY ) ) )
		status = readUniversal( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If there's validity data present, read it */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_CF_VALIDITY ) )
		{
		status = readCrmfValidity( stream, certInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the subject name and public key information */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_CF_SUBJECT ) )
		{
		readConstructed( stream, NULL, CTAG_CF_SUBJECT );
		status = readSubjectDN( stream, certInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( peekTag( stream ) != MAKE_CTAG( CTAG_CF_PUBLICKEY ) )
		status = CRYPT_ERROR_BADDATA;
	else
		/* Read the public key information.  CRMF uses yet more nonstandard 
		   tagging for the public key, in theory we'd have to read it with 
		   the CTAG_CF_PUBLICKEY tag instead of the default SEQUENCE, 
		   however the public-key-read code reads the SPKI encapsulation as 
		   a generic hole to handle this so there's no need for any special 
		   handling */
		status = readPublicKeyInfo( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, 
							CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, status ) );

	/* Read the attributes */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_CF_EXTENSIONS ) )
		{
		int length;

		status = readConstructed( stream, &length, CTAG_CF_EXTENSIONS );
		if( cryptStatusOK( status ) && length >= MIN_ATTRIBUTE_SIZE )
			status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_REQUEST_CERT, length, 
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		}

	/* Fix up any problems in attributes */
	if( cryptStatusOK( status ) )
		status = fixAttributes( certInfoPtr );

	/* CRMF requests are usually self-signed, however if they've been 
	   generated with an encryption-only key then the place of the signature
	   is taken by one of a number of magic values which indicate that no 
	   signature is present and that something else needs to be done to 
	   verify that the sender has the private key */
	tag = peekTag( stream );
	status = readConstructed( stream, NULL, tag );
	if( tag == MAKE_CTAG( 1 ) )
		/* It's a signature, the request is self-signed */
		certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
	else
		/* If it's not an indication that private-key POP will be performed 
		   by returning the cert in encrypted form, we can't handle it */
		if( tag != MAKE_CTAG( 2 ) )
			return( CRYPT_ERROR_BADDATA );
	return( status );
	}

/* Read the information in a CRMF revocation request.  We enforce the
   requirement that the request must contain at least an issuer DN and a
   serial number */

static int readRevRequestInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int length, endPos, status;

	/* Find out how much cert template is present */
	status = readSequence( stream, &length );
	endPos = stell( stream ) + length;

	/* Skip any junk before the serial number and read the serial number */
	while( cryptStatusOK( status ) && \
		   peekTag( stream ) != MAKE_CTAG_PRIMITIVE( CTAG_CF_SERIALNUMBER ) )
		status = readUniversal( stream );
	if( cryptStatusOK( status ) )
		status = readSerialNumber( stream, certInfoPtr, 
								   CTAG_CF_SERIALNUMBER );
	if( cryptStatusError( status ) )
		return( status );

	/* Skip any junk before the issuer name and read the issuer name.  We 
	   don't actually care about the contents but we have to decode them 
	   anyway in case the caller wants to view them */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_CF_SIGNINGALG ) )
		status = readUniversal( stream );
	if( cryptStatusOK( status ) )
		{
		readConstructed( stream, NULL, CTAG_CF_ISSUER );
		status = readIssuerDN( stream, certInfoPtr );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Skip any further junk that may be present in the template and read 
	   the attributes */
	while( cryptStatusOK( status ) && \
		   stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		{
		const int tag = peekTag( stream );
		
		if( tag == MAKE_CTAG( CTAG_CF_EXTENSIONS ) )
			{
			status = readConstructed( stream, &length, CTAG_CF_EXTENSIONS );
			if( cryptStatusOK( status ) && length >= MIN_ATTRIBUTE_SIZE )
				status = readAttributes( stream, &certInfoPtr->attributes,
										 CRYPT_CERTTYPE_REQUEST_REVOCATION, 
										 length, &certInfoPtr->errorLocus, 
										 &certInfoPtr->errorType );
			}
		else
			status = readUniversal( stream );
		}

	/* Fix up any problems in attributes */
	if( cryptStatusOK( status ) )
		status = fixAttributes( certInfoPtr );

	return( status );
	}

/* Read an RTCS request/response */

static int readRtcsRequestInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;
	int length, endPos, status;

	/* Read the outer wrapper and SEQUENCE OF request info and make the 
	   currently selected one the start of the list */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;
	status = readSequence( stream, &length );
	while( cryptStatusOK( status ) && length > MIN_ATTRIBUTE_SIZE )
		{
		const int innerStartPos = stell( stream );

		status = readRtcsRequestEntry( stream, &certValInfo->validityInfo, 
									   certInfoPtr );
		length -= stell( stream ) - innerStartPos;
		}
	if( cryptStatusError( status ) )
		/* The invalid attribute isn't quite a user certificate, but it's the
		   data that arose from a user certificate so it's the most 
		   appropriate locus for the error */
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
								 status ) );
	certValInfo->currentValidity = certValInfo->validityInfo;

	/* Read the extensions if there are any present.  Because some requests 
	   will have broken encoding of lengths, we allow for a bit of slop for
	   software that gets the length encoding wrong by a few bytes */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_RTCS_REQUEST, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	/* Fix up any problems in attributes */
	if( cryptStatusOK( status ) )
		status = fixAttributes( certInfoPtr );

	return( status );
	}

static int readRtcsResponseInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;
	int length, endPos, status;

	/* Read the SEQUENCE OF validity info and make the currently selected 
	   one the start of the list */
	status = readSequence( stream, &length );
	endPos = stell( stream ) + length;
	while( cryptStatusOK( status ) && length > MIN_ATTRIBUTE_SIZE )
		{
		const int innerStartPos = stell( stream );

		status = readRtcsResponseEntry( stream, &certValInfo->validityInfo, 
										certInfoPtr, FALSE );
		length -= stell( stream ) - innerStartPos;
		}
	if( cryptStatusError( status ) )
		/* The invalid attribute isn't quite a user certificate, but it's the
		   data that arose from a user certificate so it's the most 
		   appropriate locus for the error */
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
								 status ) );
	certValInfo->currentValidity = certValInfo->validityInfo;
	if( stell( stream ) > endPos - MIN_ATTRIBUTE_SIZE )
		return( CRYPT_OK );

	/* Read the extensions */
	return( readAttributes( stream, &certInfoPtr->attributes,
					CRYPT_CERTTYPE_RTCS_RESPONSE, endPos - stell( stream ),
					&certInfoPtr->errorLocus, &certInfoPtr->errorType ) );
	}

/* Read an OCSP request/response */

static int readOcspRequestInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;
	int length, endPos, status;

	/* Read the wrapper, version information, and requestor name */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;
	if( peekTag( stream ) == MAKE_CTAG( CTAG_OR_VERSION ) )
		{
		long version;

		readConstructed( stream, NULL, CTAG_OR_VERSION );
		status = readShortInteger( stream, &version );
		if( cryptStatusError( status ) )
			return( status );
		certInfoPtr->version = version + 1;	/* Zero-based */
		}
	else
		certInfoPtr->version = 1;
	if( peekTag( stream ) == MAKE_CTAG( CTAG_OR_DUMMY ) )
		readUniversal( stream );

	/* Read the SEQUENCE OF revocation info and make the currently selected 
	   one the start of the list */
	status = readSequence( stream, &length );
	while( cryptStatusOK( status ) && length > MIN_ATTRIBUTE_SIZE )
		{
		const int innerStartPos = stell( stream );

		status = readOcspRequestEntry( stream, &certRevInfo->revocations, 
									   certInfoPtr );
		length -= stell( stream ) - innerStartPos;
		}
	if( cryptStatusError( status ) )
		/* The invalid attribute isn't quite a user certificate, but it's the
		   data that arose from a user certificate so it's the most 
		   appropriate locus for the error */
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
								 status ) );
	certRevInfo->currentRevocation = certRevInfo->revocations;

	/* Read the extensions if there are any present.  Because some requests 
	   will have broken encoding of lengths, we allow for a bit of slop for
	   software that gets the length encoding wrong by a few bytes */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_OCSP_REQUEST, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	/* Fix up any problems in attributes */
	if( cryptStatusOK( status ) )
		status = fixAttributes( certInfoPtr );

	return( status );
	}

static int readOcspResponseInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;
	int length, endPos, status;

	/* Read the wrapper, version information, and responder ID */
	certInfoPtr->version = 1;
	readSequence( stream, &length );			/* tbsResponseData */
	endPos = stell( stream ) + length;
	if( peekTag( stream ) == MAKE_CTAG( CTAG_OP_VERSION ) )
		{
		long version;

		readConstructed( stream, NULL, CTAG_OP_VERSION );
		status = readShortInteger( stream, &version );
		if( cryptStatusError( status ) )
			return( status );
		certInfoPtr->version = version + 1;	/* Zero-based */
		}
	if( peekTag( stream ) == MAKE_CTAG( 1 ) )
		{
		/* It's a DN, read it as the issuer name in case the caller is 
		   interested in it */
		readConstructed( stream, NULL, 1 );
		status = readIssuerDN( stream, certInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		/* We can't do much with a key hash, in any case all current 
		   responders use the issuer DN to identify the responder so
		   this shouldn't be much of a problem */
		readUniversal( stream );
	readGeneralizedTime( stream, NULL );		/* producedAt */

	/* Read the SEQUENCE OF revocation info and make the currently selected 
	   one the start of the list */
	status = readSequence( stream, &length );
	while( cryptStatusOK( status ) && length > MIN_ATTRIBUTE_SIZE )
		{
		const int innerStartPos = stell( stream );

		status = readOcspResponseEntry( stream, &certRevInfo->revocations, 
										certInfoPtr );
		length -= stell( stream ) - innerStartPos;
		}
	if( cryptStatusError( status ) )
		/* The invalid attribute isn't quite a user certificate, but it's the
		   data that arose from a user certificate so it's the most 
		   appropriate locus for the error */
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
								 status ) );
	certRevInfo->currentRevocation = certRevInfo->revocations;

	/* Read the extensions if there are any present */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_OCSP_RESPONSE, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	/* In theory some OCSP responses can be sort of self-signed via attached
	   certs, but there are so many incompatible ways to delegate trust and 
	   signing authority mentioned in the RFC without any indication of 
	   which one implementors will follow that we require the user to supply 
	   the sig check certificate rather than assuming that some particular 
	   trust delegation mechanism will happen to be in place */
/*	certInfoPtr->flags |= CERT_FLAG_SELFSIGNED; */
	return( status );
	}

/* Read PKI user info */

static int readPkiUserInfo( STREAM *stream, CERT_INFO *userInfoPtr )
	{
	CRYPT_CONTEXT iCryptContext;
	CERT_PKIUSER_INFO *certUserInfo = userInfoPtr->cCertUser;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	ATTRIBUTE_LIST *attributeListCursor;
	QUERY_INFO queryInfo;
	STREAM userInfoStream;
	BYTE userInfo[ 128 ];
	int userInfoSize, length, status;

	/* Read the user name and encryption algorithm info and the start of the 
	   encrypted data */
	userInfoPtr->subjectDNptr = sMemBufPtr( stream );
	userInfoPtr->subjectDNsize = stell( stream );
	status = readDN( stream, &userInfoPtr->subjectName );
	userInfoPtr->subjectDNsize = stell( stream ) - userInfoPtr->subjectDNsize;
	if( cryptStatusOK( status ) )
		{
		readContextAlgoID( stream, NULL, &queryInfo, DEFAULT_TAG );
		status = readOctetString( stream, userInfo, &userInfoSize, 128 );
		if( cryptStatusOK( status ) && \
			userInfoSize != PKIUSER_ENCR_AUTHENTICATOR_SIZE )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Clone the CA key for our own use, load the IV from the encryption 
	   info, and use the cloned context to decrypt the user info.  We need to 
	   do this to prevent problems if multiple threads try to simultaneously 
	   decrypt with the CA key.  Since user objects aren't fully implemented 
	   yet, we use a fixed key as the CA key for now (most CA guidelines
	   merely require that the CA protect its user database via standard
	   (physical/ACL) security measures, so this is no less secure than what's
	   required by various CA guidelines).

	   When we do this for real we probably need an extra level of 
	   indirection to go from the CA secret to the database decryption key 
	   so that we can change the encryption algorithm and so that we don't 
	   have to directly apply the CA secret key to the user database */
	setMessageCreateObjectInfo( &createInfo, queryInfo.cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, "interop interop interop ", 24 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_KEY );
		iCryptContext = createInfo.cryptHandle;
		}
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, queryInfo.iv, queryInfo.ivLength );
		krnlSendMessage( iCryptContext,IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_IV );
		status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_DECRYPT, 
								  userInfo, userInfoSize );
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the user info.  If we get a bad data error at this point we 
	   report it as a wrong decryption key rather than bad data since it's 
	   more likely to be the former */
	sMemConnect( &userInfoStream, userInfo, userInfoSize );
	readSequence( &userInfoStream, NULL );
	readOctetString( &userInfoStream, certUserInfo->pkiIssuePW, &length,
					 PKIUSER_AUTHENTICATOR_SIZE );
	status = readOctetString( &userInfoStream, certUserInfo->pkiRevPW, 
							  &length, PKIUSER_AUTHENTICATOR_SIZE );
	sMemDisconnect( &userInfoStream );
	zeroise( userInfo, userInfoSize );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_WRONGKEY );

	/* Read the user ID and any other attributes */
	status = readAttributes( stream, &userInfoPtr->attributes, 
							 CRYPT_CERTTYPE_PKIUSER, sMemDataLeft( stream ),
							 &userInfoPtr->errorLocus, 
							 &userInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );

	/* In use the PKI user info is applied as a template to certificates to 
	   modify their contents before issue.  This is done by merging the
	   user info with the cert before it's issued.  Since there can be 
	   overlapping or conflicting attributes in the two objects, the ones in
	   the PKI user info are marked as locked to ensure that they override
	   any conflicting attributes that may be present in the cert */
	for( attributeListCursor = userInfoPtr->attributes;
		 attributeListCursor != NULL && \
			!isBlobAttribute( attributeListCursor );
		 attributeListCursor = attributeListCursor->next )
		attributeListCursor->flags |= ATTR_FLAG_LOCKED;
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read Function Access Information					*
*																			*
****************************************************************************/

const CERTREAD_INFO certReadTable[] = {
	{ CRYPT_CERTTYPE_CERTIFICATE, readCertInfo },
	{ CRYPT_CERTTYPE_ATTRIBUTE_CERT, readAttributeCertInfo },
	{ CRYPT_CERTTYPE_CERTREQUEST, readCertRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_CERT, readCrmfRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_REVOCATION, readRevRequestInfo },
	{ CRYPT_CERTTYPE_CRL, readCRLInfo },
	{ CRYPT_CERTTYPE_CMS_ATTRIBUTES, readCmsAttributes },
	{ CRYPT_CERTTYPE_RTCS_REQUEST, readRtcsRequestInfo },
	{ CRYPT_CERTTYPE_RTCS_RESPONSE, readRtcsResponseInfo },
	{ CRYPT_CERTTYPE_OCSP_REQUEST, readOcspRequestInfo },
	{ CRYPT_CERTTYPE_OCSP_RESPONSE, readOcspResponseInfo },
	{ CRYPT_CERTTYPE_PKIUSER, readPkiUserInfo },
	{ CRYPT_ICERTTYPE_CMS_CERTSET, NULL },
	{ CRYPT_ICERTTYPE_SSL_CERTCHAIN, NULL },
	{ CRYPT_CERTTYPE_NONE, NULL }
	};
