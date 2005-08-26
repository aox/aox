/****************************************************************************
*																			*
*							Certificate Write Routines						*
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

/* The X.509 version numbers */

enum { X509VERSION_1, X509VERSION_2, X509VERSION_3 };

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Add standard X.509v3 extensions to a cert if they're not already present.
   This function simply adds the required extensions, it doesn't check for
   consistency with existing extensions which is done later by checkCert() */

static int addStandardExtensions( CERT_INFO *certInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	BOOLEAN isCA = FALSE;
	int keyUsage, extKeyUsage, status;

	/* Get various pieces of information about the cert.  We do this before
	   we make any changes so that we can safely bail out if necessary.  
	   First we get the implicit key usage flags (based on any extended key 
	   usage extensions present) and explicit key usage flags.  Since these 
	   are required to be consistent, we extend the keyUsage with 
	   extKeyUsage flags further on if necessary */
	extKeyUsage = getKeyUsageFromExtKeyUsage( certInfoPtr,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
	if( cryptStatusError( extKeyUsage ) )
		return( extKeyUsage );
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   CRYPT_CERTINFO_KEYUSAGE,
										   CRYPT_ATTRIBUTE_NONE );
	keyUsage = ( attributeListPtr != NULL ) ? \
			   attributeListPtr->intValue : 0;

	/* If there's an explicit key usage present, make sure that it's
	   consistent with the implicit key usage flags derived from the extended
	   key usage.  We mask out the nonRepudiation bit for reasons given in
	   certchk.c.

	   This check is also performed by checkCert(), however we need to
	   explicitly perform it here as well since we need to add a key usage
	   to match the extKeyUsage before calling checkCert() if one wasn't
	   explicitly set or checkCert() will reject the cert because of the
	   inconsistent keyUsage */
	if( keyUsage )
		{
		const int effectiveKeyUsage = \
						extKeyUsage & ~CRYPT_KEYUSAGE_NONREPUDIATION;

		if( ( keyUsage & effectiveKeyUsage ) != effectiveKeyUsage )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* Check whether this is a CA certificate */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   CRYPT_CERTINFO_CA,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		isCA = attributeListPtr->intValue;

	/* If there's no basicConstraints present, add one and make it a non-CA
	   cert */
	if( attributeListPtr == NULL )
		{
		static const int basicConstraints = 0;

		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_CA,
								   &basicConstraints, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's no explicit keyUsage information present, add it based on
	   various implicit information.  We also add key feature information
	   which is used to help automate key management, for example to inhibit
	   speculative reads of keys held in removable tokens, which can result
	   in spurious insert-token dialogs being presented to the user outside
	   the control of cryptlib if the token isn't present */
	if( !keyUsage )
		{
		/* If there's no implicit key usage present, set the key usage flags
		   based on the algorithm type.  Because no-one can figure out what
		   the nonRepudiation flag signifies, we don't set this, if the user
		   wants it they have to specify it explicitly.  Similarly, we don't
		   try and set the keyAgreement encipher/decipher-only flags, which
		   were tacked on as variants of keyAgreement long after the basic
		   keyAgreement flag was defined */
		if( !extKeyUsage && !isCA )
			{
			if( isSigAlgo( certInfoPtr->publicKeyAlgo ) )
				keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE;
			if( isCryptAlgo( certInfoPtr->publicKeyAlgo ) )
				keyUsage |= CRYPT_KEYUSAGE_KEYENCIPHERMENT;
			if( isKeyxAlgo( certInfoPtr->publicKeyAlgo ) )
				keyUsage |= CRYPT_KEYUSAGE_KEYAGREEMENT;
			}
		else
			{
			/* Make the usage consistent with the extended usage */
			keyUsage = extKeyUsage;

			/* If it's a CA key, make sure that it's a signing key and 
			   enable its use for certification-related purposes*/
			if( isCA )
				{
				if( !isSigAlgo( certInfoPtr->publicKeyAlgo ) )
					{
					setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CA,
								  CRYPT_ERRTYPE_CONSTRAINT );
					return( CRYPT_ERROR_INVALID );
					}
				keyUsage |= CRYPT_KEYUSAGE_KEYCERTSIGN | \
							CRYPT_KEYUSAGE_CRLSIGN;
				}
			}
		assert( keyUsage );
		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
								   &keyUsage, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( certInfoPtr->publicKeyFeatures > 0 )
		{
		/* This is a bitstring so we only add it if there are feature flags
		   present to avoid writing zero-length values */
		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_KEYFEATURES,
								   &certInfoPtr->publicKeyFeatures,
								   CRYPT_UNUSED );
		if( cryptStatusError( status ) && status != CRYPT_ERROR_INITED )
			return( status );
		}

	/* Add the subjectKeyIdentifier */
	return( addCertComponent( certInfoPtr, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
							  certInfoPtr->publicKeyID, KEYID_SIZE ) );
	}

/* Prepare the entries in a cert status list prior to encoding them */

static int prepareCertStatusEntries( VALIDITY_INFO *listPtr,
									 VALIDITY_INFO **errorEntry,
									 CRYPT_ATTRIBUTE_TYPE *errorLocus,
									 CRYPT_ERRTYPE_TYPE *errorType )
	{
	VALIDITY_INFO *validityEntry;

	/* Check the attributes for each entry in a revocation list */
	for( validityEntry = listPtr; validityEntry != NULL; \
		 validityEntry = validityEntry->next )
		{
		int status;

		status = checkAttributes( ATTRIBUTE_CERTIFICATE,
								  validityEntry->attributes,
								  errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			/* Remember the entry that caused the problem */
			*errorEntry = validityEntry;
			return( status );
			}
		}

	return( CRYPT_OK );
	}

/* Prepare the entries in a revocation list prior to encoding them */

static int prepareRevocationEntries( REVOCATION_INFO *listPtr,
									 const time_t defaultTime,
									 REVOCATION_INFO **errorEntry,
									 CRYPT_ATTRIBUTE_TYPE *errorLocus,
									 CRYPT_ERRTYPE_TYPE *errorType )
	{
	REVOCATION_INFO *revocationEntry;
	const time_t currentTime = defaultTime ? defaultTime : getApproxTime();

	/* Set the revocation time if this hasn't already been set.  If there's a
	   default time set we use that, otherwise we use the current time */
	for( revocationEntry = listPtr; revocationEntry != NULL; \
		 revocationEntry = revocationEntry->next )
		{
		const ATTRIBUTE_LIST *attributeListPtr;

		if( !revocationEntry->revocationTime )
			revocationEntry->revocationTime = currentTime;

		/* Check whether the cert was revoked with a reason of neverValid,
		   which requires special handling of dates because X.509 doesn't
		   formally define a neverValid reason, assuming that all CAs are
		   perfect and never issue certs in error.  The general idea is to
		   set the two to the same value, with the invalidity date (which
		   should be earlier than the revocation date, at least in a sanely-
		   run CA) taking precedence.  A revocation with this reason code will
		   in general only be issued by the cryptlib CA (where it's required
		   to handle problems in the CMP protocol) and this always sets the
		   invalidity date, so in almost all cases we'll be setting the
		   revocation date to the (CA-specified) invalidity date, which is
		   the date of issue of the cert being revoked */
		attributeListPtr = findAttributeField( revocationEntry->attributes,
											   CRYPT_CERTINFO_CRLREASON,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && \
			attributeListPtr->intValue == CRYPT_CRLREASON_NEVERVALID )
			{
			/* The cert was revoked with the neverValid code, see if there's
			   an invalidity date present */
			attributeListPtr = \
					findAttributeField( revocationEntry->attributes,
										CRYPT_CERTINFO_INVALIDITYDATE,
										CRYPT_ATTRIBUTE_NONE );
			if( attributeListPtr == NULL )
				/* There's no invalidity date present, set it to the same as
				   the revocation date */
				addAttributeField( &revocationEntry->attributes,
								   CRYPT_CERTINFO_INVALIDITYDATE,
								   CRYPT_ATTRIBUTE_NONE,
								   &revocationEntry->revocationTime,
								   sizeof( time_t ), ATTR_FLAG_NONE,
								   NULL, NULL );
			else
				/* There's an invalidity date present, make sure the
				   revocation date is the same as the invalidity date */
				revocationEntry->revocationTime = \
						*( time_t * ) attributeListPtr->value;
			}
		}

	/* Check the attributes for each entry in a revocation list */
	for( revocationEntry = listPtr; revocationEntry != NULL; \
		 revocationEntry = revocationEntry->next )
		{
		int status;

		status = checkAttributes( ATTRIBUTE_CERTIFICATE,
								  revocationEntry->attributes,
								  errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			/* Remember the entry that caused the problem */
			*errorEntry = revocationEntry;
			return( status );
			}
		}

	return( CRYPT_OK );
	}

/* Prepare to create a certificate object */

static int preEncodeCertificate( CERT_INFO *subjectCertInfoPtr,
								 const CERT_INFO *issuerCertInfoPtr,
								 const CRYPT_CERTTYPE_TYPE type )
	{
	int status;

	/* Make sure everything is in order.  We perform the following checks for
	   the different object types:

		Object			Checks
		-----------------------------------------------
		cert			key		DN		exts	cert
		attr.cert				DN		exts	cert
		cert.req		key		DN		exts
		CRMF cert.req	key		DN(optional)
		CRMF rev.req					exts
		CRL								exts	cert
		RTCS req.						exts
		RTCS resp.						exts
		OCSP req.						exts
		OCSP resp.						exts	cert

	   Since some of the checks depend on data that isn't set up yet, we
	   break the checking up into two phases, the first one which is
	   performed immediately and the second one which is performed after
	   default and issuer-contributed attributes have been added */
	if( ( type == CRYPT_CERTTYPE_CERTIFICATE || \
		  type == CRYPT_CERTTYPE_CERTREQUEST || \
		  type == CRYPT_CERTTYPE_REQUEST_CERT ) && \
		subjectCertInfoPtr->publicKeyInfo == NULL )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}
	if( type == CRYPT_CERTTYPE_CERTIFICATE || \
		type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
		type == CRYPT_CERTTYPE_CERTREQUEST || \
		( type == CRYPT_CERTTYPE_REQUEST_CERT && \
		  subjectCertInfoPtr->subjectName != NULL ) )
		{
		/* If it's a cert request, we allow the country to be optional since
		   some CA's fill this in themselves */
		status = checkDN( subjectCertInfoPtr->subjectName, TRUE,
						  ( type == CRYPT_CERTTYPE_CERTREQUEST || \
							type == CRYPT_CERTTYPE_REQUEST_CERT ) ? TRUE : FALSE,
						  &subjectCertInfoPtr->errorLocus,
						  &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			{
			ATTRIBUTE_LIST *attributeListPtr;
			int complianceLevel;

			/* PKIX allows empty subject DNs if a subject altName is present,
			   however creating certs like this breaks every cert-using 
			   protocol supported by cryptlib so we only allow it at the
			   highest compliance level.  In addition we have to be very
			   careful to ensure that the empty subject DN can't end up 
			   becoming an empty issuer DN, for example if it's a self-signed
			   or CA cert */
			if( status != CRYPT_ERROR_NOTINITED || \
				( type == CRYPT_CERTTYPE_CERTIFICATE && \
				  subjectCertInfoPtr->cCertCert->subjectUniqueID != NULL ) || \
				( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
				return( status );
			if( cryptStatusError( \
					krnlSendMessage( subjectCertInfoPtr->ownerHandle, 
									 IMESSAGE_GETATTRIBUTE, &complianceLevel, 
									 CRYPT_OPTION_CERT_COMPLIANCELEVEL ) ) || \
				complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_FULL )
				/* We only allow this behaviour at the highest compliance 
				   level */
				return( status );
			attributeListPtr = \
				findAttributeField( subjectCertInfoPtr->attributes,
									CRYPT_CERTINFO_CA, CRYPT_ATTRIBUTE_NONE );
			if( attributeListPtr != NULL && attributeListPtr->intValue )
				/* It's a CA cert, the subject DN can't be empty */
				return( status );
			attributeListPtr = \
				findAttributeField( subjectCertInfoPtr->attributes,
									CRYPT_CERTINFO_SUBJECTALTNAME, 
									CRYPT_ATTRIBUTE_NONE );
			if( attributeListPtr == NULL )
				/* Either a subject DN or subject altName must be present */
				return( status );

			/* There's a subject altName present but no subject DN, mark the
			   altName as critical */
			attributeListPtr->flags |= ATTR_FLAG_CRITICAL;
			}

		/* If we're creating a non-self-signed cert, check whether the
		   subject's DN is the same as the issuer's DN.  If this is the case,
		   the resulting object would appear to be self-signed so we disallow
		   it */
		if( ( type == CRYPT_CERTTYPE_CERTIFICATE || \
			  type == CRYPT_CERTTYPE_ATTRIBUTE_CERT ) && \
			!( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) && \
			compareDN( issuerCertInfoPtr->subjectName,
					   subjectCertInfoPtr->subjectName, FALSE ) )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}

	/* Handle various default certificate extensions if necessary */
	if( type == CRYPT_CERTTYPE_CERTIFICATE || \
		type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		/* Constrain the subject validity period to be within the issuer
		   validity period */
		if( subjectCertInfoPtr->startTime < issuerCertInfoPtr->startTime )
			subjectCertInfoPtr->startTime = issuerCertInfoPtr->startTime;
		if( subjectCertInfoPtr->endTime > issuerCertInfoPtr->endTime )
			subjectCertInfoPtr->endTime = issuerCertInfoPtr->endTime;

		/* If it's a >= v3 cert, add the standard X.509v3 extensions if these
		   aren't already present */
		if( ( type == CRYPT_CERTTYPE_CERTIFICATE ) && \
			( subjectCertInfoPtr->version >= 3 ) )
			{
			status = addStandardExtensions( subjectCertInfoPtr );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( type == CRYPT_CERTTYPE_CERTIFICATE || \
		type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
		( type == CRYPT_CERTTYPE_CRL && issuerCertInfoPtr != NULL ) )
		{
		/* Copy the issuer DN if this isn't already present */
		if( subjectCertInfoPtr->issuerName == NULL )
			{
			status = copyDN( &subjectCertInfoPtr->issuerName,
							 issuerCertInfoPtr->subjectName );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Copy any required extensions from the issuer to the subject cert
		   if necessary */
		if( !( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
			{
			status = copyIssuerAttributes( &subjectCertInfoPtr->attributes,
										   issuerCertInfoPtr->attributes,
										   subjectCertInfoPtr->type,
										   &subjectCertInfoPtr->errorLocus,
										   &subjectCertInfoPtr->errorType );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( type == CRYPT_CERTTYPE_CRL && issuerCertInfoPtr != NULL )
		{
		/* If it's a CRL, compare the revoked cert issuer DN and signer DN
		   to make sure we're not trying to revoke someone else's certs, and
		   prepare the revocation entries */
		if( !compareDN( subjectCertInfoPtr->issuerName,
						issuerCertInfoPtr->subjectName, FALSE ) )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ERROR_INVALID );
			}
		}
	if( type == CRYPT_CERTTYPE_RTCS_RESPONSE )
		{
		/* If it's an RTCS response, prepare the cert status list entries
		   prior to encoding them */
		status = prepareCertStatusEntries( subjectCertInfoPtr->cCertVal->validityInfo,
										   &subjectCertInfoPtr->cCertVal->currentValidity,
										   &subjectCertInfoPtr->errorLocus,
										   &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( type == CRYPT_CERTTYPE_CRL || type == CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		/* If it's a CRL or OCSP response, prepare the revocation list
		   entries prior to encoding them */
		status = prepareRevocationEntries( subjectCertInfoPtr->cCertRev->revocations,
										   subjectCertInfoPtr->cCertRev->revocationTime,
										   &subjectCertInfoPtr->cCertRev->currentRevocation,
										   &subjectCertInfoPtr->errorLocus,
										   &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Now that we've set up the attributes, perform the remainder of the
	   checks.  Because RTCS is a CMS standard rather than PKIX, the RTCS 
	   attributes are CMS rather than certificate attributes */
	status = checkAttributes( ( type == CRYPT_CERTTYPE_RTCS_REQUEST ) ? \
							  ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE,
							  subjectCertInfoPtr->attributes,
							  &subjectCertInfoPtr->errorLocus,
							  &subjectCertInfoPtr->errorType );
	if( cryptStatusOK( status ) )
		status = checkCert( subjectCertInfoPtr, issuerCertInfoPtr, FALSE,
							&subjectCertInfoPtr->errorLocus,
							&subjectCertInfoPtr->errorType );
	if( cryptStatusOK( status ) && \
		( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
		  subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN ) )
		subjectCertInfoPtr->cCertCert->maxCheckLevel = \
									CRYPT_COMPLIANCELEVEL_PKIX_FULL;

	return( status );
	}

/****************************************************************************
*																			*
*							Write a Certificate Object						*
*																			*
****************************************************************************/

/* Write certificate information:

	CertificateInfo ::= SEQUENCE {
		version			  [ 0 ]	EXPLICIT INTEGER DEFAULT(0),
		serialNumber			INTEGER,
		signature				AlgorithmIdentifier,
		issuer					Name
		validity				Validity,
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		extensions		  [ 3 ]	Extensions OPTIONAL
		} */

static int writeCertInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
						  const CERT_INFO *issuerCertInfoPtr,
						  const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_CERT_INFO *certCertInfo = subjectCertInfoPtr->cCertCert;
	int length, extensionSize, status;

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded */
	subjectCertInfoPtr->issuerDNsize = \
							( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
							issuerCertInfoPtr->subjectDNsize : \
							sizeofDN( subjectCertInfoPtr->issuerName );
	subjectCertInfoPtr->subjectDNsize = \
							sizeofDN( subjectCertInfoPtr->subjectName );

	/* Determine the size of the certificate information */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = sizeofInteger( certCertInfo->serialNumber,
							certCertInfo->serialNumberLength ) + \
			 sizeofContextAlgoID( iIssuerCryptContext, certCertInfo->hashAlgo,
								  ALGOID_FLAG_ALGOID_ONLY ) + \
			 subjectCertInfoPtr->issuerDNsize + \
			 sizeofObject( sizeofUTCTime() * 2 ) + \
			 subjectCertInfoPtr->subjectDNsize + \
			 subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize > 0 )
		length += ( int ) \
				  sizeofObject( sizeofShortInteger( X509VERSION_3 ) ) + \
				  sizeofObject( sizeofObject( extensionSize ) );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If there are extensions present, mark this as a v3 certificate */
	if( extensionSize )
		{
		writeConstructed( stream, sizeofShortInteger( X509VERSION_3 ),
						  CTAG_CE_VERSION );
		writeShortInteger( stream, X509VERSION_3, DEFAULT_TAG );
		}

	/* Write the serial number and signature algorithm identifier */
	writeInteger( stream, certCertInfo->serialNumber,
				  certCertInfo->serialNumberLength, DEFAULT_TAG );
	status = writeContextAlgoID( stream, iIssuerCryptContext, 
								 certCertInfo->hashAlgo,
								 ALGOID_FLAG_ALGOID_ONLY );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the issuer name, validity period, subject name, and public key
	   information */
	if( issuerCertInfoPtr->subjectDNptr != NULL )
		swrite( stream, issuerCertInfoPtr->subjectDNptr,
				issuerCertInfoPtr->subjectDNsize );
	else
		{
		status = writeDN( stream, subjectCertInfoPtr->issuerName, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}
	writeSequence( stream, sizeofUTCTime() * 2 );
	writeUTCTime( stream, subjectCertInfoPtr->startTime, DEFAULT_TAG );
	writeUTCTime( stream, subjectCertInfoPtr->endTime, DEFAULT_TAG );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = swrite( stream, subjectCertInfoPtr->publicKeyInfo,
						 subjectCertInfoPtr->publicKeyInfoSize );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the extensions */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_CERTIFICATE, extensionSize ) );
	}

/* Write attribute certificate information:

	AttributeCertificateInfo ::= SEQUENCE {
		version					INTEGER DEFAULT(1),
		owner			  [ 1 ]	Name,
		issuer					Name,
		signature				AlgorithmIdentifier,
		serialNumber			INTEGER,
		validity				Validity,
		attributes				SEQUENCE OF Attribute,
		extensions				Extensions OPTIONAL
		} */

static int writeAttributeCertInfo( STREAM *stream,
								   CERT_INFO *subjectCertInfoPtr,
								   const CERT_INFO *issuerCertInfoPtr,
								   const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_CERT_INFO *certCertInfo = subjectCertInfoPtr->cCertCert;
	int length, extensionSize, issuerNameSize, status;

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_ATTRIBUTE_CERT );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded */
	issuerNameSize = ( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
					 issuerCertInfoPtr->subjectDNsize : \
					 sizeofDN( subjectCertInfoPtr->issuerName );

	/* Determine the size of the certificate information */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = ( int ) sizeofObject( sizeofDN( subjectCertInfoPtr->subjectName ) ) + \
			 issuerNameSize + \
			 sizeofContextAlgoID( iIssuerCryptContext, certCertInfo->hashAlgo,
								  ALGOID_FLAG_ALGOID_ONLY ) + \
			 sizeofInteger( certCertInfo->serialNumber,
							certCertInfo->serialNumberLength ) + \
			 sizeofObject( sizeofUTCTime() * 2 ) + \
			 sizeofObject( 0 ) + \
			 ( extensionSize ? ( int ) sizeofObject( extensionSize ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* Write the owner and issuer name */
	writeConstructed( stream, sizeofDN( subjectCertInfoPtr->subjectName ),
					  CTAG_AC_ENTITYNAME );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		if( issuerCertInfoPtr->subjectDNptr != NULL )
			swrite( stream, issuerCertInfoPtr->subjectDNptr,
					issuerCertInfoPtr->subjectDNsize );
		else
			status = writeDN( stream, subjectCertInfoPtr->issuerName, DEFAULT_TAG );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the signature algorithm identifier, serial number and validity
	   period */
	writeContextAlgoID( stream, iIssuerCryptContext, certCertInfo->hashAlgo,
						ALGOID_FLAG_ALGOID_ONLY );
	writeInteger( stream, certCertInfo->serialNumber,
				  certCertInfo->serialNumberLength, DEFAULT_TAG );
	writeSequence( stream, sizeofUTCTime() * 2 );
	writeUTCTime( stream, subjectCertInfoPtr->startTime, DEFAULT_TAG );
	writeUTCTime( stream, subjectCertInfoPtr->endTime, DEFAULT_TAG );

	/* Write the attributes */
	status = writeSequence( stream, 0 );
	if( extensionSize <= 0 )
		return( status );

	/* Write the extensions */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_ATTRIBUTE_CERT, extensionSize ) );
	}

/* Write certificate request information:

	CertificationRequestInfo ::= SEQUENCE {
		version					INTEGER (0),
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		attributes		  [ 0 ]	SET OF Attribute
		}

   If extensions are present they are encoded as:

	SEQUENCE {							-- Attribute from X.501
		OBJECT IDENTIFIER {pkcs-9 14},	--   type
		SET OF {						--   values
			SEQUENCE OF {				-- ExtensionReq from CMMF draft
				<X.509v3 extensions>
				}
			}
		}

   as per the CMMF draft */

static int writeCertRequestInfo( STREAM *stream,
								 CERT_INFO *subjectCertInfoPtr,
								 const CERT_INFO *issuerCertInfoPtr,
								 const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int length, extensionSize, status;

	assert( issuerCertInfoPtr == NULL );

	/* Make sure everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_CERTREQUEST );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = sizeofShortInteger( 0 ) + \
			 sizeofDN( subjectCertInfoPtr->subjectName ) + \
			 subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize > 0 )
		length += ( int ) \
				  sizeofObject( \
					sizeofObject( \
						sizeofOID( OID_PKCS9_EXTREQ ) + \
						sizeofObject( sizeofObject( extensionSize ) ) ) );
	else
		length += ( int ) sizeofObject( 0 );

	/* Write the header, version number, DN, and public key info */
	writeSequence( stream, length );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = swrite( stream, subjectCertInfoPtr->publicKeyInfo,
						 subjectCertInfoPtr->publicKeyInfoSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the attributes.  If there are no attributes, we have to write
	   an (erroneous) zero-length field */
	if( extensionSize <= 0 )
		return( writeConstructed( stream, 0, CTAG_CR_ATTRIBUTES ) );
	writeConstructed( stream, ( int ) \
					  sizeofObject( \
						sizeofOID( OID_PKCS9_EXTREQ ) + \
						sizeofObject( sizeofObject( extensionSize ) ) ),
					  CTAG_CR_ATTRIBUTES );
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_CERTREQUEST, extensionSize ) );
	}

/* Write CRMF certificate request information:

	CertReq ::= SEQUENCE {
		certReqID				INTEGER (0),
		certTemplate			SEQUENCE {
			validity	  [ 4 ]	SEQUENCE {
				validFrom [ 0 ]	EXPLICIT GeneralizedTime OPTIONAL,
				validTo	  [ 1 ] EXPLICIT GeneralizedTime OPTIONAL
				} OPTIONAL,
			subject		  [ 5 ]	EXPLICIT Name OPTIONAL,
			publicKey	  [ 6 ]	SubjectPublicKeyInfo,
			extensions	  [ 9 ]	SET OF Attribute OPTIONAL
			}
		} */

static int writeCrmfRequestInfo( STREAM *stream,
								 CERT_INFO *subjectCertInfoPtr,
								 const CERT_INFO *issuerCertInfoPtr,
								 const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int payloadLength, extensionSize, subjectDNsize = 0, timeSize = 0;
	int status = CRYPT_OK;

	assert( issuerCertInfoPtr == NULL );

	/* Make sure everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_REQUEST_CERT );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	if( subjectCertInfoPtr->subjectName != NULL )
		subjectCertInfoPtr->subjectDNsize = subjectDNsize = \
								sizeofDN( subjectCertInfoPtr->subjectName );
	if( subjectCertInfoPtr->startTime )
		timeSize = ( int ) sizeofObject( sizeofGeneralizedTime() );
	if( subjectCertInfoPtr->endTime )
		timeSize += ( int ) sizeofObject( sizeofGeneralizedTime() );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	payloadLength = ( timeSize ? ( int ) sizeofObject( timeSize ) : 0 ) + \
					( subjectDNsize ? ( int ) sizeofObject( subjectDNsize ) : 0 ) + \
					subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize )
		payloadLength += ( int ) sizeofObject( extensionSize );

	/* Write the header, request ID, inner header, DN, and public key */
	writeSequence( stream, sizeofShortInteger( 0 ) + \
				   sizeofObject( payloadLength ) );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeSequence( stream, payloadLength );
	if( timeSize )
		{
		writeConstructed( stream, timeSize, CTAG_CF_VALIDITY );
		if( subjectCertInfoPtr->startTime )
			{
			writeConstructed( stream, sizeofGeneralizedTime(), 0 );
			writeGeneralizedTime( stream, subjectCertInfoPtr->startTime,
								  DEFAULT_TAG );
			}
		if( subjectCertInfoPtr->endTime )
			{
			writeConstructed( stream, sizeofGeneralizedTime(), 1 );
			writeGeneralizedTime( stream, subjectCertInfoPtr->endTime,
								  DEFAULT_TAG );
			}
		}
	if( subjectDNsize )
		{
		writeConstructed( stream, subjectCertInfoPtr->subjectDNsize,
						  CTAG_CF_SUBJECT );
		status = writeDN( stream, subjectCertInfoPtr->subjectName,
						  DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( !sIsNullStream( stream ) )
		{
		BYTE *dataPtr = sMemBufPtr( stream );

		/* Convert the SPKI SEQUENCE tag to the CRMF alternative */
		swrite( stream, subjectCertInfoPtr->publicKeyInfo,
				subjectCertInfoPtr->publicKeyInfoSize );
		*dataPtr = MAKE_CTAG( CTAG_CF_PUBLICKEY );
		}
	else
		swrite( stream, subjectCertInfoPtr->publicKeyInfo,
				subjectCertInfoPtr->publicKeyInfoSize );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	writeConstructed( stream, extensionSize, CTAG_CF_EXTENSIONS );
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_REQUEST_CERT, extensionSize ) );
	}

/* Write CMP revocation request information:

	RevDetails ::= SEQUENCE {
		certTemplate			SEQUENCE {
			serialNumber  [ 1 ]	INTEGER,
			issuer		  [ 3 ]	EXPLICIT Name,
			},
		crlEntryDetails			SET OF Attribute
		} */

static int writeRevRequestInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
								const CERT_INFO *issuerCertInfoPtr,
								const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int payloadLength, extensionSize, status;

	assert( issuerCertInfoPtr == NULL );
	assert( iIssuerCryptContext == CRYPT_UNUSED );

	/* Make sure everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_REQUEST_REVOCATION );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	payloadLength = sizeofInteger( subjectCertInfoPtr->cCertCert->serialNumber,
								   subjectCertInfoPtr->cCertCert->serialNumberLength ) + \
					sizeofObject( subjectCertInfoPtr->issuerDNsize ) + \
					( extensionSize ? ( int ) sizeofObject( extensionSize ) : 0 );

	/* Write the header, inner header, serial number and issuer DN */
	writeSequence( stream, sizeofObject( payloadLength ) );
	writeSequence( stream, payloadLength );
	writeInteger( stream, subjectCertInfoPtr->cCertCert->serialNumber,
				  subjectCertInfoPtr->cCertCert->serialNumberLength,
				  CTAG_CF_SERIALNUMBER );
	writeConstructed( stream, subjectCertInfoPtr->issuerDNsize,
					  CTAG_CF_ISSUER );
	status = swrite( stream, subjectCertInfoPtr->issuerDNptr,
					 subjectCertInfoPtr->issuerDNsize );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	writeConstructed( stream, extensionSize, CTAG_CF_EXTENSIONS );
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_REQUEST_REVOCATION, extensionSize ) );
	}

/* Write CRL information:

	CRLInfo ::= SEQUENCE {
		version					INTEGER DEFAULT(0),
		signature				AlgorithmIdentifier,
		issuer					Name,
		thisUpdate				UTCTime,
		nextUpdate				UTCTime OPTIONAL,
		revokedCertificates		SEQUENCE OF RevokedCerts,
		extensions		  [ 0 ]	Extensions OPTIONAL
		} */

static int writeCRLInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
						 const CERT_INFO *issuerCertInfoPtr,
						 const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	REVOCATION_INFO *revocationInfo;
	int length, extensionSize, revocationInfoLength = 0, status;

	assert( ( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) && \
			  isHandleRangeValid( iIssuerCryptContext ) ) || \
			( issuerCertInfoPtr == NULL && \
			  iIssuerCryptContext == CRYPT_UNUSED ) );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_CRL );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process CRL entries and version information */
	subjectCertInfoPtr->version = \
					( subjectCertInfoPtr->attributes != NULL ) ? 2 : 1;
	for( revocationInfo = certRevInfo->revocations;
		 revocationInfo != NULL; revocationInfo = revocationInfo->next )
		{
		if( revocationInfo->attributes != NULL )
			/* If there are per-entry extensions present it's a v2 CRL */
			subjectCertInfoPtr->version = 2;
		revocationInfoLength += sizeofCRLentry( revocationInfo );
		}

	/* If we're being asked to write a single CRL entry, we don't try and go
	   any further since the remaining CRL fields (and issuer info) may not
	   be set up */
	if( issuerCertInfoPtr == NULL )
		return( writeCRLentry( stream, certRevInfo->currentRevocation ) );

	/* Determine how big the encoded CRL will be */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = sizeofContextAlgoID( iIssuerCryptContext, certRevInfo->hashAlgo,
								  ALGOID_FLAG_ALGOID_ONLY ) + \
			 issuerCertInfoPtr->subjectDNsize + sizeofUTCTime() + \
			 ( subjectCertInfoPtr->endTime ? sizeofUTCTime() : 0 ) + \
			 sizeofObject( revocationInfoLength );
	if( extensionSize > 0 )
		length += sizeofShortInteger( X509VERSION_2 ) + \
			 	  ( int ) sizeofObject( sizeofObject( extensionSize ) );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If there are extensions present, mark this as a v2 CRL */
	if( extensionSize )
		writeShortInteger( stream, X509VERSION_2, DEFAULT_TAG );

	/* Write the signature algorithm identifier, issuer name, and CRL time */
	status = writeContextAlgoID( stream, iIssuerCryptContext, 
								 certRevInfo->hashAlgo,
								 ALGOID_FLAG_ALGOID_ONLY );
	if( cryptStatusError( status ) )
		return( status );
	swrite( stream, issuerCertInfoPtr->subjectDNptr,
			issuerCertInfoPtr->subjectDNsize );
	writeUTCTime( stream, subjectCertInfoPtr->startTime, DEFAULT_TAG );
	if( subjectCertInfoPtr->endTime )
		writeUTCTime( stream, subjectCertInfoPtr->endTime, DEFAULT_TAG );

	/* Write the SEQUENCE OF revoked certificates wrapper and the revoked
	   certificate information */
	status = writeSequence( stream, revocationInfoLength );
	for( revocationInfo = certRevInfo->revocations;
		 cryptStatusOK( status ) && revocationInfo != NULL;
		 revocationInfo = revocationInfo->next )
		status = writeCRLentry( stream, revocationInfo );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the extensions */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_CRL, extensionSize ) );
	}

/* Write CMS attributes */

static int writeCmsAttributes( STREAM *stream, CERT_INFO *attributeInfoPtr,
							   const CERT_INFO *issuerCertInfoPtr,
							   const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int addDefaultAttributes, attributeSize, status;

	UNUSED( issuerCertInfoPtr );

	krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE,
					 &addDefaultAttributes,
					 CRYPT_OPTION_CMS_DEFAULTATTRIBUTES );

	/* Make sure there's a hash and content type present */
	if( findAttributeField( attributeInfoPtr->attributes,
							CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
							CRYPT_ATTRIBUTE_NONE ) == NULL )
		{
		setErrorInfo( attributeInfoPtr, CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_INVALID );
		}
	if( !checkAttributePresent( attributeInfoPtr->attributes,
								CRYPT_CERTINFO_CMS_CONTENTTYPE ) )
		{
		const int value = CRYPT_CONTENT_DATA;

		/* If there's no content type and we're not adding it automatically,
		   complain */
		if( !addDefaultAttributes )
			{
			setErrorInfo( attributeInfoPtr, CRYPT_CERTINFO_CMS_CONTENTTYPE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_INVALID );
			}

		/* There's no content type present, treat it as straight data (which
		   means this is signedData) */
		status = addCertComponent( attributeInfoPtr, CRYPT_CERTINFO_CMS_CONTENTTYPE,
								   &value, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's no signing time attribute present and we're adding the
	   default attributes, add it now.  This will usually already have been
	   added by the caller via getReliableTime(), if it hasn't then we
	   default to using the system time source because the signing object
	   isn't available at this point to provide a time source */
	if( addDefaultAttributes && \
		!checkAttributePresent( attributeInfoPtr->attributes,
								CRYPT_CERTINFO_CMS_SIGNINGTIME ) )
		{
		const time_t currentTime = getTime();

		/* If the time is screwed up we can't provide a signed indication
		   of the time */
		if( currentTime < MIN_TIME_VALUE )
			{
			setErrorInfo( attributeInfoPtr, CRYPT_CERTINFO_VALIDFROM,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ERROR_NOTINITED );
			}

		status = addCertComponent( attributeInfoPtr, CRYPT_CERTINFO_CMS_SIGNINGTIME,
								   &currentTime, sizeof( time_t ) );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check that the attributes are in order and determine how big the whole
	   mess will be */
	status = checkAttributes( ATTRIBUTE_CMS, attributeInfoPtr->attributes,
							  &attributeInfoPtr->errorLocus,
							  &attributeInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	attributeSize = sizeofAttributes( attributeInfoPtr->attributes );

	/* Write the attributes */
	return( writeAttributes( stream, attributeInfoPtr->attributes,
							 CRYPT_CERTTYPE_CMS_ATTRIBUTES, attributeSize ) );
	}

/* Write an RTCS request:

	RTCSRequests ::= SEQUENCE {
		SEQUENCE OF SEQUENCE {
			certHash	OCTET STRING SIZE(20)
			},
		attributes		Attributes OPTIONAL
		} */

static int writeRtcsRequestInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
								 const CERT_INFO *issuerCertInfoPtr,
								 const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_VAL_INFO *certValInfo = subjectCertInfoPtr->cCertVal;
	VALIDITY_INFO *validityInfo;
	int length, extensionSize, requestInfoLength = 0, status;

	/* Make sure that we've actually got some requests present to write */
	if( certValInfo->validityInfo == NULL )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Perform any necessary pre-encoding steps.  We should really update the
	   nonce when we write the data for real, but to do that we'd have to re-
	   calculate the extension information (via preEncodeCertifiate()) for
	   null-stream and real writes just because the one extension changes, so
	   we calculate it when we do the dummy write instead.  This is safe
	   because the write process always performs a real write immediately
	   after the null-stream write */
	if( sIsNullStream( stream ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;
		RESOURCE_DATA msgData;

		/* To ensure freshness we always use a new nonce when we write an
		   RTCS request */
		attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
											   CRYPT_CERTINFO_CMS_NONCE,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			setMessageData( &msgData, attributeListPtr->value, 16 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			attributeListPtr->valueLength = 16;
			}
		else
			{
			BYTE nonce[ CRYPT_MAX_HASHSIZE ];

			setMessageData( &msgData, nonce, 16 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			if( cryptStatusOK( status ) )
				status = addAttributeField( &subjectCertInfoPtr->attributes,
											CRYPT_CERTINFO_CMS_NONCE,
											CRYPT_ATTRIBUTE_NONE, nonce, 16,
											ATTR_FLAG_NONE, NULL, NULL );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* Perform the pre-encoding checks */
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
									   CRYPT_CERTTYPE_RTCS_REQUEST );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded RTCS request will be */
	for( validityInfo = certValInfo->validityInfo;
		 validityInfo != NULL; validityInfo = validityInfo->next )
		requestInfoLength += sizeofRtcsRequestEntry( validityInfo );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = sizeofObject( requestInfoLength ) + \
			 ( extensionSize ? sizeofObject( extensionSize ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* Write the SEQUENCE OF request wrapper and the request information */
	status = writeSequence( stream, requestInfoLength );
	for( validityInfo = certValInfo->validityInfo;
		 cryptStatusOK( status ) && validityInfo != NULL;
		 validityInfo = validityInfo->next )
		status = writeRtcsRequestEntry( stream, validityInfo );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_RTCS_REQUEST, extensionSize ) );
	}

/* Write an RTCS response:

	RTCSResponse ::= SEQUENCE {
		SEQUENCE OF SEQUENCE {
			certHash	OCTET STRING SIZE(20),
			RESPONSEINFO
			}
		} */

static int writeRtcsResponseInfo( STREAM *stream,
								  CERT_INFO *subjectCertInfoPtr,
								  const CERT_INFO *issuerCertInfoPtr,
								  const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_VAL_INFO *certValInfo = subjectCertInfoPtr->cCertVal;
	VALIDITY_INFO *validityInfo;
	int length = 0, extensionSize, validityInfoLength = 0, status;

	/* RTCS can legitimately return an empty response if there's a problem
	   with the responder, so we don't require that any responses be present
	   as for CRLs/OCSP */

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
									   CRYPT_CERTTYPE_RTCS_RESPONSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP response will be */
	for( validityInfo = certValInfo->validityInfo;
		 validityInfo != NULL; validityInfo = validityInfo->next )
		validityInfoLength += \
			sizeofRtcsResponseEntry( validityInfo,
					certValInfo->responseType == RTCSRESPONSE_TYPE_EXTENDED );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length += ( int ) sizeofObject( validityInfoLength ) + \
			  ( extensionSize ? sizeofObject( extensionSize ) : 0 );

	/* Write the SEQUENCE OF status information wrapper and the cert status
	   information */
	status = writeSequence( stream, validityInfoLength );
	for( validityInfo = certValInfo->validityInfo;
		 cryptStatusOK( status ) && validityInfo != NULL;
		 validityInfo = validityInfo->next )
		{
		status = writeRtcsResponseEntry( stream, validityInfo,
					certValInfo->responseType == RTCSRESPONSE_TYPE_EXTENDED );
		}
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_RTCS_RESPONSE, extensionSize ) );
	}

/* Write an OCSP request:

	OCSPRequest ::= SEQUENCE {				-- Write, v1
		reqName		[1]	EXPLICIT [4] EXPLICIT DirectoryName OPTIONAL,
		reqList			SEQUENCE OF SEQUENCE {
						SEQUENCE {			-- certID
			hashAlgo	AlgorithmIdentifier,
			iNameHash	OCTET STRING,
			iKeyHash	OCTET STRING,
			serialNo	INTEGER
			} }
		}

	OCSPRequest ::= SEQUENCE {				-- Write, v2
		version		[0]	EXPLICIT INTEGER (1),
		reqName		[1]	EXPLICIT [4] EXPLICIT DirectoryName OPTIONAL,
		reqList			SEQUENCE OF SEQUENCE {
			certID	[2]	EXPLICIT OCTET STRING	-- Cert hash
			}
		} */

static int writeOcspRequestInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
								 const CERT_INFO *issuerCertInfoPtr,
								 const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	REVOCATION_INFO *revocationInfo;
	int length, extensionSize, revocationInfoLength = 0, status;

	/* Make sure that we've actually got some requests present to write */
	if( certRevInfo->revocations == NULL )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Perform any necessary pre-encoding steps.  We should really update the
	   nonce when we write the data for real, but to do that we'd have to re-
	   calculate the extension information (via preEncodeCertifiate()) for
	   null-stream and real writes just because the one extension changes, so
	   we calculate it when we do the dummy write instead.  This is safe
	   because the write process always performs a real write immediately
	   after the null-stream write */
	if( sIsNullStream( stream ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;
		RESOURCE_DATA msgData;

		/* To ensure freshness we always use a new nonce when we write an
		   OCSP request.  We don't check for problems (which, in any case,
		   could only occur if there's an out-of-memory error) because
		   there's not much we can meaningfully do if the add fails */
		attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
											   CRYPT_CERTINFO_OCSP_NONCE,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			setMessageData( &msgData, attributeListPtr->value, 16 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			attributeListPtr->valueLength = 16;
			}
		else
			{
			BYTE nonce[ CRYPT_MAX_HASHSIZE ];

			setMessageData( &msgData, nonce, 16 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			if( cryptStatusOK( status ) )
				status = addAttributeField( &subjectCertInfoPtr->attributes,
											CRYPT_CERTINFO_OCSP_NONCE,
											CRYPT_ATTRIBUTE_NONE, nonce, 16,
											ATTR_FLAG_NONE, NULL, NULL );
			attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
												   CRYPT_CERTINFO_OCSP_NONCE,
												   CRYPT_ATTRIBUTE_NONE );
			}
		if( cryptStatusError( status ) )
			return( status );
		if( attributeListPtr != NULL )
			{
			BYTE *noncePtr = attributeListPtr->value;

			/* Because of OCSP's inexplicable use of integers to encode the
			   nonce octet string, we have to tweak the first byte to ensure
			   that the integer encoding works as a standard OCTET STRING */
			noncePtr[ 0 ] &= 0x7F;
			if( !noncePtr[ 0 ] )
				noncePtr[ 0 ]++;
			}

		/* Perform the pre-encoding checks */
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
									   CRYPT_CERTTYPE_OCSP_REQUEST );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP request will be */
	for( revocationInfo = certRevInfo->revocations;
		 revocationInfo != NULL; revocationInfo = revocationInfo->next )
		revocationInfoLength += sizeofOcspRequestEntry( revocationInfo );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = ( ( subjectCertInfoPtr->version == 2 ) ? \
				 sizeofObject( sizeofShortInteger( CTAG_OR_VERSION ) ) : 0 ) + \
			 ( ( issuerCertInfoPtr != NULL ) ? \
				 sizeofObject( sizeofObject( issuerCertInfoPtr->subjectDNsize ) ) : 0 ) + \
			 sizeofObject( revocationInfoLength ) + \
			 ( extensionSize ? \
			   sizeofObject( sizeofObject( extensionSize ) ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If we're using v2 identifiers, mark this as a v2 request */
	if( subjectCertInfoPtr->version == 2 )
		{
		writeConstructed( stream, sizeofShortInteger( 1 ), CTAG_OR_VERSION );
		writeShortInteger( stream, 1, DEFAULT_TAG );
		}

	/* If we're signing the request, write the issuer DN as a GeneralName */
	if( issuerCertInfoPtr != NULL )
		{
		writeConstructed( stream,
						  sizeofObject( issuerCertInfoPtr->subjectDNsize ), 1 );
		writeConstructed( stream, issuerCertInfoPtr->subjectDNsize, 4 );
		swrite( stream, issuerCertInfoPtr->subjectDNptr,
				issuerCertInfoPtr->subjectDNsize );
		}

	/* Write the SEQUENCE OF revocation information wrapper and the
	   revocation information */
	status = writeSequence( stream, revocationInfoLength );
	for( revocationInfo = certRevInfo->revocations;
		 cryptStatusOK( status ) && revocationInfo != NULL;
		 revocationInfo = revocationInfo->next )
		status = writeOcspRequestEntry( stream, revocationInfo );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_OCSP_REQUEST, extensionSize ) );
	}

/* Write an OCSP response:

	OCSPResponse ::= SEQUENCE {
		version		[0]	EXPLICIT INTEGER (1),
		respID		[1]	EXPLICIT Name,
		producedAt		GeneralizedTime,
		responses		SEQUENCE OF Response
		exts		[1]	EXPLICIT Extensions OPTIONAL,
		}

	RTCSResponse ::= SEQUENCE {
		responses		SEQUENCE OF Response,
		exts			Extensions OPTIONAL
		} */

static int writeOcspResponseInfo( STREAM *stream,
								  CERT_INFO *subjectCertInfoPtr,
								  const CERT_INFO *issuerCertInfoPtr,
								  const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	REVOCATION_INFO *revocationInfo;
	int length = 0, extensionSize, revocationInfoLength = 0, status;

	/* Make sure that we've actually got some responses present to write */
	if( certRevInfo->revocations == NULL )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
									   CRYPT_CERTTYPE_OCSP_RESPONSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP response will be */
	for( revocationInfo = certRevInfo->revocations;
		 revocationInfo != NULL; revocationInfo = revocationInfo->next )
		revocationInfoLength += sizeofOcspResponseEntry( revocationInfo );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = ( int ) \
			 sizeofObject( sizeofShortInteger( CTAG_OP_VERSION ) ) + \
			 sizeofObject( issuerCertInfoPtr->subjectDNsize ) + \
			 sizeofGeneralizedTime() + \
			 sizeofObject( revocationInfoLength ) + \
			 ( extensionSize ? \
				sizeofObject( sizeofObject( extensionSize ) ) : 0 );

	/* Write the outer SEQUENCE wrapper, and, if it's an OCSP response, mark
	   it as a v1 response and write the issuer DN and producedAt time */
	writeSequence( stream, length );
	writeConstructed( stream, sizeofShortInteger( 1 ), CTAG_OP_VERSION );
	writeShortInteger( stream, 1, DEFAULT_TAG );
	writeConstructed( stream, issuerCertInfoPtr->subjectDNsize, 1 );
	swrite( stream, issuerCertInfoPtr->subjectDNptr,
			issuerCertInfoPtr->subjectDNsize );
	writeGeneralizedTime( stream, subjectCertInfoPtr->startTime,
						  DEFAULT_TAG );

	/* Write the SEQUENCE OF revocation information wrapper and the
	   revocation information */
	status = writeSequence( stream, revocationInfoLength );
	for( revocationInfo = certRevInfo->revocations;
		 cryptStatusOK( status ) && revocationInfo != NULL;
		 revocationInfo = revocationInfo->next )
		status = writeOcspResponseEntry( stream, revocationInfo,
										 subjectCertInfoPtr->startTime );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_OCSP_RESPONSE, extensionSize ) );
	}

/* Write PKI user info */

int writePkiUserInfo( STREAM *stream, CERT_INFO *userInfoPtr,
					  const CERT_INFO *issuerCertInfoPtr,
					  const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_PKIUSER_INFO *certUserInfo = userInfoPtr->cCertUser;
	BYTE userInfo[ 128 ], algoID[ 128 ];
	int extensionSize, userInfoSize, algoIDsize, status;

	UNUSED( issuerCertInfoPtr );

	if( sIsNullStream( stream ) )
		{
		RESOURCE_DATA msgData;
		BYTE keyID[ 16 ];
		int keyIDlength;

		/* Generate the key identifier.  Once it's in user-encoded form the
		   full identifier can't quite fit so we adjust the size to the
		   maximum amount we can encode.  This is necessary because it's
		   also used to locate the user info in a key store, if we used the
		   un-adjusted form for the key ID we couldn't locate the stored
		   user info using the adjusted form */
		setMessageData( &msgData, keyID, 16 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		keyIDlength = adjustPKIUserValue( keyID, 3 );
		addAttributeField( &userInfoPtr->attributes,
						   CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
						   CRYPT_ATTRIBUTE_NONE, keyID, keyIDlength,
						   ATTR_FLAG_NONE, NULL, NULL );
		status = checkAttributes( ATTRIBUTE_CERTIFICATE,
								  userInfoPtr->attributes,
								  &userInfoPtr->errorLocus,
								  &userInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );

		/* We can't generate the user info yet since we're doing the pre-
		   encoding pass and writing to a null stream so we leave it for the
		   actual encoding pass and only provide a size estimate for now */
		userInfoSize = PKIUSER_ENCR_AUTHENTICATOR_SIZE;

		/* Since we can't use the fixed CA key yet, we set the algo ID size
		   to the size of the info for the fixed 3DES key */
		algoIDsize = 22;
		}
	else
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;
		RESOURCE_DATA msgData;
		STREAM userInfoStream;

		/* Create an RC4 context and use it to generate the user passwords.
		   These aren't encryption keys but just authenticators used for
		   MACing so we don't go to the usual extremes to protect them */
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_RC4 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		sMemOpen( &userInfoStream, userInfo, 128 );
		writeSequence( &userInfoStream,
					   2 * sizeofObject( PKIUSER_AUTHENTICATOR_SIZE ) );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_GENKEY,
								  NULL, FALSE );
		if( cryptStatusOK( status ) )
			{
			krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_ENCRYPT,
							 certUserInfo->pkiIssuePW,
							 PKIUSER_AUTHENTICATOR_SIZE );
			writeOctetString( &userInfoStream, certUserInfo->pkiIssuePW,
							  PKIUSER_AUTHENTICATOR_SIZE, DEFAULT_TAG );
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_CTX_ENCRYPT,
									  certUserInfo->pkiRevPW,
									  PKIUSER_AUTHENTICATOR_SIZE );
			writeOctetString( &userInfoStream, certUserInfo->pkiRevPW,
							  PKIUSER_AUTHENTICATOR_SIZE, DEFAULT_TAG );
			userInfoSize = stell( &userInfoStream );
			}
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		sMemDisconnect( &userInfoStream );
		if( cryptStatusError( status ) )
			return( status );

		/* Encrypt the user info.  Since user objects aren't fully
		   implemented yet, we use a fixed key as the CA key for now.  When
		   user objects are fully implemented, we'd need to lock the CA key
		   around the following operations */
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_3DES );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		setMessageData( &msgData, "interop interop interop ", 24 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusOK( status ) )
			{
			int i;

			/* Add PKCS #5 padding to the end of the user info and encrypt
			   it */
			assert( userInfoSize + 2 == PKIUSER_ENCR_AUTHENTICATOR_SIZE );
			for( i = 0; i < 2; i++ )
				userInfo[ userInfoSize++ ] = 2;
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_CTX_GENIV );
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_CTX_ENCRYPT, userInfo,
									  userInfoSize );
			if( cryptStatusOK( status ) )
				{
				STREAM algoIDstream;

				sMemOpen( &algoIDstream, algoID, 128 );
				status = writeContextAlgoID( &algoIDstream,
									createInfo.cryptHandle, CRYPT_ALGO_NONE,
									ALGOID_FLAG_NONE );
				algoIDsize = stell( &algoIDstream );
				sMemDisconnect( &algoIDstream );
				}
			}
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the user DN, encrypted user info, and any supplementary
	   information */
	extensionSize = sizeofAttributes( userInfoPtr->attributes );
	writeDN( stream, userInfoPtr->subjectName, DEFAULT_TAG );
	swrite( stream, algoID, algoIDsize );
	writeOctetString( stream, userInfo, userInfoSize, DEFAULT_TAG );
	return( writeAttributes( stream, userInfoPtr->attributes,
							 CRYPT_CERTTYPE_PKIUSER, extensionSize ) );
	}

/****************************************************************************
*																			*
*						Read Function Access Information					*
*																			*
****************************************************************************/

const CERTWRITE_INFO certWriteTable[] = {
	{ CRYPT_CERTTYPE_CERTIFICATE, writeCertInfo },
	{ CRYPT_CERTTYPE_CERTCHAIN, writeCertInfo },
	{ CRYPT_CERTTYPE_ATTRIBUTE_CERT, writeAttributeCertInfo },
	{ CRYPT_CERTTYPE_CERTREQUEST, writeCertRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_CERT, writeCrmfRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_REVOCATION, writeRevRequestInfo },
	{ CRYPT_CERTTYPE_CRL, writeCRLInfo },
	{ CRYPT_CERTTYPE_CMS_ATTRIBUTES, writeCmsAttributes },
	{ CRYPT_CERTTYPE_RTCS_REQUEST, writeRtcsRequestInfo },
	{ CRYPT_CERTTYPE_RTCS_RESPONSE, writeRtcsResponseInfo },
	{ CRYPT_CERTTYPE_OCSP_REQUEST, writeOcspRequestInfo },
	{ CRYPT_CERTTYPE_OCSP_RESPONSE, writeOcspResponseInfo },
	{ CRYPT_CERTTYPE_PKIUSER, writePkiUserInfo },
	{ CRYPT_CERTTYPE_NONE, NULL }
	};
