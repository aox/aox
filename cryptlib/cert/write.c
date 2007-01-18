/****************************************************************************
*																			*
*							Certificate Write Routines						*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
  #include "asn1_ext.h"
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

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

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
	   chk_cert.c.

	   This check is also performed by checkCert(), however we need to
	   explicitly perform it here as well since we need to add a key usage
	   to match the extKeyUsage before calling checkCert() if one wasn't
	   explicitly set or checkCert() will reject the cert because of the
	   inconsistent keyUsage */
	if( keyUsage > 0 )
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
		isCA = ( attributeListPtr->intValue > 0 ) ? TRUE : FALSE;

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
	if( keyUsage <= 0 )
		{
		/* If there's no implicit key usage present, set the key usage flags
		   based on the algorithm type.  Because no-one can figure out what
		   the nonRepudiation flag signifies, we don't set this, if the user
		   wants it they have to specify it explicitly.  Similarly, we don't
		   try and set the keyAgreement encipher/decipher-only flags, which
		   were tacked on as variants of keyAgreement long after the basic
		   keyAgreement flag was defined */
		if( extKeyUsage <= 0 && !isCA )
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
		assert( keyUsage > 0 );
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

/****************************************************************************
*																			*
*							Pre-encode Checking Functions					*
*																			*
****************************************************************************/

/* Check whether an empty DN is permitted in a certificate */

static BOOLEAN checkEmptyDnOK( CERT_INFO *subjectCertInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int complianceLevel;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	/* PKIX allows empty subject DNs if a subject altName is present, 
	   however creating certs like this breaks every cert-using protocol 
	   supported by cryptlib so we only allow it at the highest compliance 
	   level */
	if( cryptStatusError( \
			krnlSendMessage( subjectCertInfoPtr->ownerHandle,
							 IMESSAGE_GETATTRIBUTE, &complianceLevel,
							 CRYPT_OPTION_CERT_COMPLIANCELEVEL ) ) || \
		complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_FULL )
		/* We only allow this behaviour at the highest compliance level */
		return( FALSE );
	   
	/* We also have to be very careful to ensure that the empty subject 
	   DN can't end up becoming an empty issuer DN, which can occur if it's 
	   a self-signed cert */
	if( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED )
		/* We can't have an empty issuer (== subject) DN */
		return( FALSE );

	/* In addition if it's a CA cert the subject DN can't be empty, for 
	   obvious reasons */
	attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && attributeListPtr->intValue > 0 )
		/* It's a CA cert, the subject DN can't be empty */
		return( FALSE );

	/* Finally, if there's no subject DN present there has to be an altName
	   present to take its place */
	attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
										   CRYPT_CERTINFO_SUBJECTALTNAME,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr == NULL )
		/* Either a subject DN or subject altName must be present */
		return( FALSE );

	/* There's a subject altName present but no subject DN, mark the altName 
	   as critical */
	attributeListPtr->flags |= ATTR_FLAG_CRITICAL;

	return( TRUE );
	}

/* Before we encode a certificate object, we have to perform various final 
   setup actions and perform checks to ensure that the object is ready for
   encoding.  The following setup operations and checks can be requested by
   the caller:

	CHECK_DN: Full subject DN is present.

	CHECK_DN_PARTIAL: Partial subject DN is present.  This is a DN template,
		so the full DN doesn't have to be present since the CA can fill in
		the rest later.

	CHECK_ISSUERDN: Issuer DN is present.

	CHECK_ISSUERCERTDN: Issuer cert's subject DN == subject cert's issuer DN.

	CHECK_NONSELFSIGNEDDN: Cert's subject DN != cert's issuer DN, which would
		make it appear to be a self-signed cert.

	CHECK_REVENTRIES: At least one revocation entry is present.

	CHECK_SERIALNO: Serial number is present.

	CHECK_SPKI: SubjectPublicKeyInfo is present.

	CHECK_VALENTRIES: At least one validity entry is present.

	SET_ISSUERATTR: Copy issuer attributes to subject.

	SET_ISSUERDN: Copy issuer DN to subject.

	SET_REVINFO: Set up revocation info.

	SET_STANDARDATTR: Set up standard extensions/attributes.

	SET_VALIDITYPERIOD: Constrain subject validity to issuer validity.

	SET_VALINFO: Set up validity info */

#define PRE_CHECK_NONE			0x0000	/* No check actions */
#define PRE_CHECK_SPKI			0x0001	/* SPKI present */
#define PRE_CHECK_DN			0x0002	/* Subject DN present */
#define PRE_CHECK_DN_PARTIAL	0x0004	/* Partial subject DN present */
#define PRE_CHECK_ISSUERDN		0x0008	/* Issuer DN present */
#define PRE_CHECK_ISSUERCERTDN	0x0010	/* Issuer cert DN == subj.issuer DN */
#define PRE_CHECK_NONSELFSIGNED_DN 0x0020	/* Issuer DN != subject DN */
#define PRE_CHECK_SERIALNO		0x0040	/* SerialNo present */
#define PRE_CHECK_VALENTRIES	0x0080	/* Validity entries present */
#define PRE_CHECK_REVENTRIES	0x0100	/* Revocation entries present */

#define PRE_SET_NONE			0x0000	/* No setup actions */
#define PRE_SET_STANDARDATTR	0x0001	/* Set up standard extensions */
#define PRE_SET_ISSUERATTR		0x0002	/* Copy issuer attr.to subject */
#define PRE_SET_ISSUERDN		0x0004	/* Copy issuer DN to subject */
#define PRE_SET_VALIDITYPERIOD	0x0008	/* Constrain subj.val.to issuer val.*/
#define PRE_SET_VALINFO			0x0010	/* Set up validity info */
#define PRE_SET_REVINFO			0x0020	/* Set up revocation info */

/* Additional flags that control the operations indicated above */

#define PRE_FLAG_NONE			0x0000	/* No special control options */
#define PRE_FLAG_DN_IN_ISSUERCERT 0x0001/* Issuer DN is in issuer cert */

/* The checks for the different object types are:

				|  Cert	|  Attr	|  P10	|Cr.Req	|Rv.Req	
	------------+-------+-------+-------+-------+-------+
	STDATTR		|	X	|		|		|		|		|
	ISSUERATTR	|	X	|	X	|		|		|		|
	ISSUERDN	|	X	|	X	|		|		|		|
	VALPERIOD	|	X	|	X	|		|		|		|
	VALINFO		|		|		|		|		|		|
	REVINFO		|		|		|		|		|		|
	------------+-------+-------+-------+-------+-------+
	SPKI		|	X	|		|	X	|	X	|		|
	DN			|	X	|	X	|		|		|		|
	DN_PART		|		|		|	X	|	X	|		|
	ISSUERDN	|	X	|	X	|		|		|	X	|
	ISSUERCRTDN	|		|		|		|		|		|
	NON_SELFSD	|	X	|	X	|		|		|		|
	SERIALNO	|	X	|	X	|		|		|	X	|
	REVENTRIES	|		|		|		|		|		|
	------------+-------+-------+-------+-------+-------+

				|RTCS Rq|RTCS Rs|OCSP Rq|OCSP Rs|  CRL	|CRLentr|
	------------+-------+-------+-------+-------+-------+-------+
	STDATTR		|		|		|		|		|		|		|
	ISSUERATTR	|		|		|		|		|	X	|		|
	ISSUERDN	|		|		|		|		|	X	|		|
	VALPERIOD	|		|		|		|		|		|		|
	VALINFO		|	X	|		|		|		|		|		|
	REVINFO		|		|		|	X	|		|	X	|	X	|
	------------+-------+-------+-------+-------+-------+-------+
	SPKI		|		|		|		|		|		|		|
	DN			|		|		|		|	X	|		|		|
	DN_PART		|		|		|		|		|		|		|
	ISSUERDN	|		|		|		|		|	X	|		|
	ISSUERCRTDN	|		|		|		|		|	X	|		|
	NON_SELFSD	|		|		|		|		|		|		|
	SERIALNO	|		|		|		|		|		|		|
	VALENTRIES	|	X	|		|		|		|		|		|
	REVENTRIES	|		|		|	X	|	X	|		|		|
	------------+-------+-------+-------+-------+-------+-------+ */

static int preEncodeCertificate( CERT_INFO *subjectCertInfoPtr,
								 const CERT_INFO *issuerCertInfoPtr,
								 const int setActions, 
								 const int checkActions, const int flags )
	{
	int status;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( issuerCertInfoPtr == NULL ) || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( setActions >= 0 );
	assert( checkActions >= 0 );
	assert( ( flags == PRE_FLAG_NONE ) || \
			( flags == PRE_FLAG_DN_IN_ISSUERCERT ) );

	/* Make sure that everything is in order.  Some of the checks depend on 
	   data that isn't set up yet, so first perform all of the setup actions
	   that add default and issuer-contributed attributes, and then perform
	   all of the checks */
	if( setActions & PRE_SET_STANDARDATTR )
		{
		/* If it's a >= v3 cert, add the standard X.509v3 extensions if these
		   aren't already present */
		if( subjectCertInfoPtr->version >= 3 )
			{
			status = addStandardExtensions( subjectCertInfoPtr );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( setActions & PRE_SET_ISSUERATTR )
		{
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
	if( setActions & PRE_SET_ISSUERDN )
		{
		/* Copy the issuer DN if this isn't already present */
		if( subjectCertInfoPtr->issuerName == NULL )
			{
			status = copyDN( &subjectCertInfoPtr->issuerName,
							 issuerCertInfoPtr->subjectName );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( setActions & PRE_SET_VALIDITYPERIOD )
		{
		/* Constrain the subject validity period to be within the issuer
		   validity period */
		if( subjectCertInfoPtr->startTime < issuerCertInfoPtr->startTime )
			subjectCertInfoPtr->startTime = issuerCertInfoPtr->startTime;
		if( subjectCertInfoPtr->endTime > issuerCertInfoPtr->endTime )
			subjectCertInfoPtr->endTime = issuerCertInfoPtr->endTime;
		}
	if( setActions & PRE_SET_VALINFO )
		{
		/* If it's an RTCS response, prepare the cert status list entries
		   prior to encoding them */
		status = prepareValidityEntries( subjectCertInfoPtr->cCertVal->validityInfo,
										 &subjectCertInfoPtr->cCertVal->currentValidity,
										 &subjectCertInfoPtr->errorLocus,
										 &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( setActions & PRE_SET_REVINFO )
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

	/* Now that everything's set up, check that the object is reading for 
	   encoding */
	if( checkActions & PRE_CHECK_SPKI )
		{
		/* Make sure that there's public-key info present */
		if( subjectCertInfoPtr->publicKeyInfo == NULL )
			{
			setErrorInfo( subjectCertInfoPtr, 
						  CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}
	if( checkActions & PRE_CHECK_DN )
		{
		/* Make sure that there's a full DN present */
		status = checkDN( subjectCertInfoPtr->subjectName, TRUE, FALSE,
						  &subjectCertInfoPtr->errorLocus,
						  &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			{
			/* In some very special cases an empty DN is permitted, so we
			   only return an error if this really isn't allowed */
			if( status != CRYPT_ERROR_NOTINITED || \
				!checkEmptyDnOK( subjectCertInfoPtr ) )
				return( status );
			}
		}
	if( checkActions & PRE_CHECK_DN_PARTIAL )
		{
		/* Make sure that there's at least a partial DN present (some CA's 
		   will fill the remainder themselves) */
		status = checkDN( subjectCertInfoPtr->subjectName, TRUE, TRUE,
						  &subjectCertInfoPtr->errorLocus,
						  &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( checkActions & PRE_CHECK_ISSUERDN )
		{
		if( flags & PRE_FLAG_DN_IN_ISSUERCERT )
			{
			if( issuerCertInfoPtr == NULL || \
				issuerCertInfoPtr->subjectDNptr == NULL || \
				issuerCertInfoPtr->subjectDNsize < 1 )
				{
				setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			}
		else
			{
			/* The issuer DN can be present either in pre-encoded form (if
			   it was copied from an issuer cert) or as a full DN (if it's
			   a self-signed cert), so we check for the presence of either */
			if( ( subjectCertInfoPtr->issuerName == NULL ) && 
				( subjectCertInfoPtr->issuerDNptr == NULL || \
				  subjectCertInfoPtr->issuerDNsize < 1 ) )
				{
				setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			}
		}
	if( checkActions & PRE_CHECK_ISSUERCERTDN )
		{
		/* If it's a CRL, compare the revoked cert issuer DN and signer DN
		   to make sure that we're not trying to revoke someone else's certs, 
		   and prepare the revocation entries */
		if( !compareDN( subjectCertInfoPtr->issuerName,
						issuerCertInfoPtr->subjectName, FALSE ) )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ERROR_INVALID );
			}
		}
	if( checkActions & PRE_CHECK_NONSELFSIGNED_DN )
		{
		/* If we're creating a non-self-signed cert, check whether the
		   subject's DN is the same as the issuer's DN.  If this is the case,
		   the resulting object would appear to be self-signed so we disallow
		   it */
		if( compareDN( issuerCertInfoPtr->subjectName,
					   subjectCertInfoPtr->subjectName, FALSE ) )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}
	if( checkActions & PRE_CHECK_SERIALNO )
		{
		if( subjectCertInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION )
			{
			if( subjectCertInfoPtr->cCertReq->serialNumberLength <= 0 )
				{
				setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SERIALNUMBER,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			}
		else
			{
			if( subjectCertInfoPtr->cCertCert->serialNumberLength <= 0 )
				{
				setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SERIALNUMBER,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			}
		}
	if( checkActions & PRE_CHECK_VALENTRIES )
		{
		if( subjectCertInfoPtr->cCertVal->validityInfo == NULL )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}
	if( checkActions & PRE_CHECK_REVENTRIES )
		{
		if( subjectCertInfoPtr->cCertRev->revocations == NULL )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}

	/* Now that we've set up the attributes, perform the remainder of the
	   checks.  Because RTCS is a CMS standard rather than PKIX, the RTCS
	   attributes are CMS rather than certificate attributes */
	status = checkAttributes( ( subjectCertInfoPtr->type == \
								CRYPT_CERTTYPE_RTCS_REQUEST ) ? \
							  ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE,
							  subjectCertInfoPtr->attributes,
							  &subjectCertInfoPtr->errorLocus,
							  &subjectCertInfoPtr->errorType );
	if( cryptStatusOK( status ) )
		status = checkCert( subjectCertInfoPtr, issuerCertInfoPtr, FALSE,
							&subjectCertInfoPtr->errorLocus,
							&subjectCertInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a cert or certchain, remember that it's been checked at full
	   compliance level.  This short-circuits the need to perform excessive
	   levels of checking if the caller wants to re-check it after it's been
	   signed */
	if( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
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
	const int algoIdInfoSize = \
			sizeofContextAlgoID( iIssuerCryptContext, certCertInfo->hashAlgo,
								 ALGOID_FLAG_ALGOID_ONLY );
	int length, extensionSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isHandleRangeValid( iIssuerCryptContext ) );

	if( cryptStatusError( algoIdInfoSize ) )
		return( algoIdInfoSize  );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
						PRE_SET_STANDARDATTR | PRE_SET_ISSUERATTR | \
						PRE_SET_ISSUERDN | PRE_SET_VALIDITYPERIOD, 
						PRE_CHECK_SPKI | PRE_CHECK_DN | \
						PRE_CHECK_ISSUERDN | PRE_CHECK_SERIALNO | \
						( ( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) ? \
							0 : PRE_CHECK_NONSELFSIGNED_DN ),
						( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
							PRE_FLAG_DN_IN_ISSUERCERT : PRE_FLAG_NONE );
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
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = sizeofInteger( certCertInfo->serialNumber,
							certCertInfo->serialNumberLength ) + \
			 algoIdInfoSize + \
			 subjectCertInfoPtr->issuerDNsize + \
			 sizeofObject( sizeofUTCTime() * 2 ) + \
			 subjectCertInfoPtr->subjectDNsize + \
			 subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize > 0 )
		length += sizeofObject( sizeofShortInteger( X509VERSION_3 ) ) + \
				  sizeofObject( sizeofObject( extensionSize ) );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If there are extensions present, mark this as a v3 certificate */
	if( extensionSize > 0 )
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
		status = swrite( stream, issuerCertInfoPtr->subjectDNptr,
						 issuerCertInfoPtr->subjectDNsize );
	else
		status = writeDN( stream, subjectCertInfoPtr->issuerName, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
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
	const int algoIdInfoSize = \
			sizeofContextAlgoID( iIssuerCryptContext, certCertInfo->hashAlgo,
								 ALGOID_FLAG_ALGOID_ONLY );
	int length, extensionSize, issuerNameSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isHandleRangeValid( iIssuerCryptContext ) );

	if( cryptStatusError( algoIdInfoSize ) )
		return( algoIdInfoSize  );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
						PRE_SET_ISSUERDN | PRE_SET_ISSUERATTR | \
						PRE_SET_VALIDITYPERIOD, 
						PRE_CHECK_DN | PRE_CHECK_ISSUERDN | \
						PRE_CHECK_SERIALNO | \
						( ( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) ? \
							0 : PRE_CHECK_NONSELFSIGNED_DN ),
						( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
							PRE_FLAG_DN_IN_ISSUERCERT : PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded */
	issuerNameSize = ( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
					 issuerCertInfoPtr->subjectDNsize : \
					 sizeofDN( subjectCertInfoPtr->issuerName );

	/* Determine the size of the certificate information */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = ( int ) sizeofObject( sizeofDN( subjectCertInfoPtr->subjectName ) ) + \
			 issuerNameSize + \
			 algoIdInfoSize + \
			 sizeofInteger( certCertInfo->serialNumber,
							certCertInfo->serialNumberLength ) + \
			 sizeofObject( sizeofUTCTime() * 2 ) + \
			 sizeofObject( 0 ) + \
			 ( ( extensionSize > 0 ) ? \
				( int ) sizeofObject( extensionSize ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* Write the owner and issuer name */
	writeConstructed( stream, sizeofDN( subjectCertInfoPtr->subjectName ),
					  CTAG_AC_ENTITYNAME );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		if( issuerCertInfoPtr->subjectDNptr != NULL )
			status = swrite( stream, issuerCertInfoPtr->subjectDNptr,
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
		} */

static int writeCertRequestInfo( STREAM *stream,
								 CERT_INFO *subjectCertInfoPtr,
								 const CERT_INFO *issuerCertInfoPtr,
								 const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int length, extensionSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL );
	assert( isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Make sure that everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
						PRE_SET_NONE, 
						PRE_CHECK_SPKI | PRE_CHECK_DN_PARTIAL,
						PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = sizeofShortInteger( 0 ) + \
			 sizeofDN( subjectCertInfoPtr->subjectName ) + \
			 subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize > 0 )
		length += sizeofObject( \
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

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL );
	assert( isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Make sure that everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
						PRE_SET_NONE, 
						PRE_CHECK_SPKI | \
						( ( subjectCertInfoPtr->subjectName != NULL ) ? \
							PRE_CHECK_DN_PARTIAL : 0 ),
						PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	if( subjectCertInfoPtr->subjectName != NULL )
		subjectCertInfoPtr->subjectDNsize = subjectDNsize = \
								sizeofDN( subjectCertInfoPtr->subjectName );
	if( subjectCertInfoPtr->startTime > MIN_TIME_VALUE )
		timeSize = sizeofObject( sizeofGeneralizedTime() );
	if( subjectCertInfoPtr->endTime > MIN_TIME_VALUE )
		timeSize += sizeofObject( sizeofGeneralizedTime() );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	payloadLength = ( ( timeSize > 0 ) ? sizeofObject( timeSize ) : 0 ) + \
					( ( subjectDNsize > 0 ) ? sizeofObject( subjectDNsize ) : 0 ) + \
					subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize )
		payloadLength += sizeofObject( extensionSize );

	/* Write the header, request ID, inner header, DN, and public key */
	writeSequence( stream, sizeofShortInteger( 0 ) + \
				   sizeofObject( payloadLength ) );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeSequence( stream, payloadLength );
	if( timeSize > 0 )
		{
		writeConstructed( stream, timeSize, CTAG_CF_VALIDITY );
		if( subjectCertInfoPtr->startTime > MIN_TIME_VALUE )
			{
			writeConstructed( stream, sizeofGeneralizedTime(), 0 );
			writeGeneralizedTime( stream, subjectCertInfoPtr->startTime,
								  DEFAULT_TAG );
			}
		if( subjectCertInfoPtr->endTime > MIN_TIME_VALUE )
			{
			writeConstructed( stream, sizeofGeneralizedTime(), 1 );
			writeGeneralizedTime( stream, subjectCertInfoPtr->endTime,
								  DEFAULT_TAG );
			}
		}
	if( subjectDNsize > 0 )
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

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL );
	assert( iIssuerCryptContext == CRYPT_UNUSED );

	/* Make sure that everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
						PRE_SET_NONE, 
						PRE_CHECK_ISSUERDN | PRE_CHECK_SERIALNO,
						PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	payloadLength = sizeofInteger( subjectCertInfoPtr->cCertCert->serialNumber,
								   subjectCertInfoPtr->cCertCert->serialNumberLength ) + \
					sizeofObject( subjectCertInfoPtr->issuerDNsize ) + \
					( ( extensionSize > 0 ) ? \
						sizeofObject( extensionSize ) : 0 );

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
	const BOOLEAN isCrlEntry = ( issuerCertInfoPtr == NULL ) ? TRUE : FALSE;
	int length, algoIdInfoSize, extensionSize, revocationInfoLength = 0;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( issuerCertInfoPtr == NULL && \
			  iIssuerCryptContext == CRYPT_UNUSED ) || \
			( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) && \
			  isHandleRangeValid( iIssuerCryptContext ) ) );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
						( isCrlEntry ? 0 : \
							PRE_SET_ISSUERDN | PRE_SET_ISSUERATTR ) | \
						PRE_SET_REVINFO, 
						( isCrlEntry ? 0 : PRE_CHECK_ISSUERCERTDN | \
										   PRE_CHECK_ISSUERDN ),
						PRE_FLAG_DN_IN_ISSUERCERT );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process CRL entries and version information */
	subjectCertInfoPtr->version = \
					( subjectCertInfoPtr->attributes != NULL ) ? 2 : 1;
	for( revocationInfo = certRevInfo->revocations;
		 revocationInfo != NULL; revocationInfo = revocationInfo->next )
		{
		const int crlEntrySize = sizeofCRLentry( revocationInfo );

		if( cryptStatusError( crlEntrySize ) )
			return( crlEntrySize );
		revocationInfoLength += crlEntrySize;

		/* If there are per-entry extensions present it's a v2 CRL */
		if( revocationInfo->attributes != NULL )
			subjectCertInfoPtr->version = 2;
		}

	/* If we're being asked to write a single CRL entry, we don't try and go
	   any further since the remaining CRL fields (and issuer info) may not
	   be set up */
	if( isCrlEntry )
		return( writeCRLentry( stream, certRevInfo->currentRevocation ) );

	/* Determine how big the encoded CRL will be */
	algoIdInfoSize = sizeofContextAlgoID( iIssuerCryptContext, 
										  certRevInfo->hashAlgo, 
										  ALGOID_FLAG_ALGOID_ONLY );
	if( cryptStatusError( algoIdInfoSize ) )
		return( algoIdInfoSize  );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = algoIdInfoSize + \
			 issuerCertInfoPtr->subjectDNsize + sizeofUTCTime() + \
			 ( ( subjectCertInfoPtr->endTime > MIN_TIME_VALUE ) ? \
				sizeofUTCTime() : 0 ) + \
			 sizeofObject( revocationInfoLength );
	if( extensionSize > 0 )
		length += sizeofShortInteger( X509VERSION_2 ) + \
			 	  sizeofObject( sizeofObject( extensionSize ) );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If there are extensions present, mark this as a v2 CRL */
	if( extensionSize > 0 )
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
	if( subjectCertInfoPtr->endTime > MIN_TIME_VALUE )
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

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL );
	assert( iIssuerCryptContext == CRYPT_UNUSED );

	krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE,
					 &addDefaultAttributes,
					 CRYPT_OPTION_CMS_DEFAULTATTRIBUTES );

	/* Make sure that there's a hash and content type present */
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
		   means that this is signedData) */
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
		if( currentTime <= MIN_TIME_VALUE )
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
	if( cryptStatusError( attributeSize ) )
		return( attributeSize );

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
	int length, extensionSize, requestInfoLength = 0;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL );
	assert( iIssuerCryptContext == CRYPT_UNUSED );

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
		MESSAGE_DATA msgData;

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
			BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];

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
						PRE_SET_NONE, 
						PRE_CHECK_VALENTRIES,
						PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded RTCS request will be */
	iterationCount = 0;
	for( validityInfo = certValInfo->validityInfo;
		 validityInfo != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_LARGE; 
		 validityInfo = validityInfo->next )
		{
		const int requestEntrySize = sizeofRtcsRequestEntry( validityInfo );
		
		if( cryptStatusError( requestEntrySize ) )
			return( requestEntrySize );
		requestInfoLength += requestEntrySize;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = sizeofObject( requestInfoLength ) + \
			 ( ( extensionSize > 0 ) ? sizeofObject( extensionSize ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* Write the SEQUENCE OF request wrapper and the request information */
	status = writeSequence( stream, requestInfoLength );
	iterationCount = 0;
	for( validityInfo = certValInfo->validityInfo;
		 cryptStatusOK( status ) && validityInfo != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_LARGE; 
		 validityInfo = validityInfo->next )
		{
		status = writeRtcsRequestEntry( stream, validityInfo );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
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
	int length = 0, extensionSize, validityInfoLength = 0;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL );
	assert( iIssuerCryptContext == CRYPT_UNUSED );

	/* RTCS can legitimately return an empty response if there's a problem
	   with the responder, so we don't require that any responses be present
	   as for CRLs/OCSP */

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
						PRE_SET_VALINFO, 
						PRE_CHECK_NONE,
						PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded RTCS response will be */
	iterationCount = 0;
	for( validityInfo = certValInfo->validityInfo;
		 validityInfo != NULL && iterationCount++ < FAILSAFE_ITERATIONS_LARGE; 
		 validityInfo = validityInfo->next )
		{
		const int responseEntrySize = \
			sizeofRtcsResponseEntry( validityInfo,
					certValInfo->responseType == RTCSRESPONSE_TYPE_EXTENDED );

		if( cryptStatusError( responseEntrySize ) )
			return( responseEntrySize );
		validityInfoLength += responseEntrySize;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length += sizeofObject( validityInfoLength ) + \
			  ( ( extensionSize > 0 ) ? sizeofObject( extensionSize ) : 0 );

	/* Write the SEQUENCE OF status information wrapper and the cert status
	   information */
	status = writeSequence( stream, validityInfoLength );
	iterationCount = 0;
	for( validityInfo = certValInfo->validityInfo;
		 cryptStatusOK( status ) && validityInfo != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_LARGE; 
		 validityInfo = validityInfo->next )
		{
		status = writeRtcsResponseEntry( stream, validityInfo,
					certValInfo->responseType == RTCSRESPONSE_TYPE_EXTENDED );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
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
	int length, extensionSize, revocationInfoLength = 0;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( issuerCertInfoPtr == NULL ) || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( iIssuerCryptContext == CRYPT_UNUSED ) || \
			( isHandleRangeValid( iIssuerCryptContext ) ) );/* Not used here */

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
		MESSAGE_DATA msgData;

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
			BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];

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
			if( noncePtr[ 0 ] == 0 )
				noncePtr[ 0 ]++;
			}

		/* Perform the pre-encoding checks */
		if( issuerCertInfoPtr != NULL )
			{
			/* It's a signed request, there has to be an issuer DN present */
			status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
							PRE_SET_REVINFO, 
							PRE_CHECK_ISSUERDN | PRE_CHECK_REVENTRIES,
							PRE_FLAG_DN_IN_ISSUERCERT );
			}
		else
			status = preEncodeCertificate( subjectCertInfoPtr, NULL,
							PRE_SET_REVINFO, 
							PRE_CHECK_REVENTRIES,
							PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP request will be */
	iterationCount = 0;
	for( revocationInfo = certRevInfo->revocations;
		 revocationInfo != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_LARGE;
		 revocationInfo = revocationInfo->next )
		{
		const int requestEntrySize = sizeofOcspRequestEntry( revocationInfo );

		if( cryptStatusError( requestEntrySize ) )
			return( requestEntrySize );
		revocationInfoLength += requestEntrySize;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = ( ( subjectCertInfoPtr->version == 2 ) ? \
				 sizeofObject( sizeofShortInteger( CTAG_OR_VERSION ) ) : 0 ) + \
			 ( ( issuerCertInfoPtr != NULL ) ? \
				 sizeofObject( sizeofObject( issuerCertInfoPtr->subjectDNsize ) ) : 0 ) + \
			 sizeofObject( revocationInfoLength ) + \
			 ( ( extensionSize > 0 ) ? \
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
	iterationCount = 0;
	for( revocationInfo = certRevInfo->revocations;
		 cryptStatusOK( status ) && revocationInfo != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_LARGE;
		 revocationInfo = revocationInfo->next )
		{
		status = writeOcspRequestEntry( stream, revocationInfo );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
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
		} */

static int writeOcspResponseInfo( STREAM *stream,
								  CERT_INFO *subjectCertInfoPtr,
								  const CERT_INFO *issuerCertInfoPtr,
								  const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	REVOCATION_INFO *revocationInfo;
	int length = 0, extensionSize, revocationInfoLength = 0;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
						PRE_SET_NONE, 
						PRE_CHECK_ISSUERDN | PRE_CHECK_REVENTRIES,
						PRE_FLAG_DN_IN_ISSUERCERT );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP response will be */
	iterationCount = 0;
	for( revocationInfo = certRevInfo->revocations;
		 revocationInfo != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_LARGE; 
		 revocationInfo = revocationInfo->next )
		{
		const int responseEntrySize = sizeofOcspResponseEntry( revocationInfo );

		if( cryptStatusError( responseEntrySize ) )
			return( responseEntrySize );
		revocationInfoLength += responseEntrySize;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = sizeofObject( sizeofShortInteger( CTAG_OP_VERSION ) ) + \
			 sizeofObject( issuerCertInfoPtr->subjectDNsize ) + \
			 sizeofGeneralizedTime() + \
			 sizeofObject( revocationInfoLength ) + \
			 ( ( extensionSize > 0 ) ? \
				sizeofObject( sizeofObject( extensionSize ) ) : 0 );

	/* Write the outer SEQUENCE wrapper, version, and issuer DN and 
	   producedAt time */
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
	iterationCount = 0;
	for( revocationInfo = certRevInfo->revocations;
		 cryptStatusOK( status ) && revocationInfo != NULL && \
			iterationCount++ < FAILSAFE_ITERATIONS_LARGE; 
		 revocationInfo = revocationInfo->next )
		{
		status = writeOcspResponseEntry( stream, revocationInfo,
										 subjectCertInfoPtr->startTime );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		retIntError();
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
	BYTE userInfo[ 128 + 8 ], algoID[ 128 + 8 ];
	int extensionSize, userInfoSize, algoIDsize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( userInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL );
	assert( iIssuerCryptContext == CRYPT_UNUSED );

	if( sIsNullStream( stream ) )
		{
		MESSAGE_DATA msgData;
		BYTE keyID[ 16 + 8 ];
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
		static const CRYPT_MODE_TYPE mode = CRYPT_MODE_CFB;
		MESSAGE_CREATEOBJECT_INFO createInfo;
		MESSAGE_DATA msgData;
		STREAM userInfoStream;

		/* Create a stream-cipher encryption context and use it to generate
		   the user passwords.  These aren't encryption keys but just
		   authenticators used for MACing so we don't go to the usual
		   extremes to protect them.  In addition we can't use the most
		   obvious option for the stream cipher, RC4, since this may be
		   disabled in some builds, so we rely on 3DES which is always
		   available */
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_3DES );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		sMemOpen( &userInfoStream, userInfo, 128 );
		writeSequence( &userInfoStream,
					   2 * sizeofObject( PKIUSER_AUTHENTICATOR_SIZE ) );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE,
								  ( void * ) &mode, CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_CTX_GENKEY, NULL, FALSE );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_CTX_GENIV, NULL, 0 );
		if( cryptStatusOK( status ) )
			{
			memset( certUserInfo->pkiIssuePW, 0, PKIUSER_AUTHENTICATOR_SIZE );
			krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_ENCRYPT,
							 certUserInfo->pkiIssuePW,
							 PKIUSER_AUTHENTICATOR_SIZE );
			writeOctetString( &userInfoStream, certUserInfo->pkiIssuePW,
							  PKIUSER_AUTHENTICATOR_SIZE, DEFAULT_TAG );
			memset( certUserInfo->pkiRevPW, 0, PKIUSER_AUTHENTICATOR_SIZE );
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
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
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

static const CERTWRITE_INFO FAR_BSS certWriteTable[] = {
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

const CERTWRITE_INFO *getCertWriteTable( void )
	{
	return( certWriteTable );
	}

int sizeofCertWriteTable( void )
	{
	return( FAILSAFE_ARRAYSIZE( certWriteTable, CERTWRITE_INFO ) );
	}
