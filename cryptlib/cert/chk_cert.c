/****************************************************************************
*																			*
*						  Certificate Checking Routines						*
*						Copyright Peter Gutmann 1997-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#elif defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Check whether a policy is the wildcard anyPolicy */

static BOOLEAN isAnyPolicy( const ATTRIBUTE_LIST *attributeListPtr )
	{
	return( ( attributeListPtr->valueLength == sizeofOID( OID_ANYPOLICY ) && \
			  !memcmp( attributeListPtr->value, OID_ANYPOLICY, 
					   sizeofOID( OID_ANYPOLICY ) ) ) ? TRUE : FALSE );
	}

/* Check whether a set of policies contains an instance of the anyPolicy
   wildcard */

static BOOLEAN containsAnyPolicy( const ATTRIBUTE_LIST *attributeListPtr,
								  const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	for( attributeListPtr = findAttributeField( attributeListPtr, \
								attributeType, CRYPT_ATTRIBUTE_NONE ); \
		 attributeListPtr != NULL; \
		 attributeListPtr = findNextFieldInstance( attributeListPtr ) )
		if( isAnyPolicy( attributeListPtr ) )
			return( TRUE );

	return( FALSE );
	}

/* Check the type of policy present in a cert */

static BOOLEAN checkPolicyType( const ATTRIBUTE_LIST *attributeListPtr,
								BOOLEAN *hasPolicy, BOOLEAN *hasAnyPolicy,
								const BOOLEAN inhibitAnyPolicy )
	{
	/* Clear return values */
	*hasPolicy = *hasAnyPolicy = FALSE;

	/* Make sure that there's a policy present, and that it's a specific 
	   policy if an explicit policy is required (the ability to disallow the 
	   wildcard policy via inhibitAnyPolicy was introduced in RFC 3280 along 
	   with the introduction of anyPolicy) */
	if( attributeListPtr == NULL )
		return( FALSE );
	while( attributeListPtr != NULL )
		{
		assert( attributeListPtr->fieldID == CRYPT_CERTINFO_CERTPOLICYID );

		if( isAnyPolicy( attributeListPtr ) )
			*hasAnyPolicy = TRUE;
		else
			*hasPolicy = TRUE;
		attributeListPtr = findNextFieldInstance( attributeListPtr );
		}
	if( inhibitAnyPolicy )
		{
		/* The wildcard anyPolicy isn't valid for the subject, if there's no
		   other policy set this is an error, otherwise we continue without
		   the wildcard match allowed */
		if( !*hasPolicy )
			return( FALSE );
		*hasAnyPolicy = FALSE;
		}

	return( TRUE );
	}

/* Check whether disallowed CA-only attributes are present in a (non-CA) 
   attribute list.  We report the error as a constraint derived from the CA
   flag rather than the attribute itself, since it's the absence of the flag 
   that renders the presence of the attribute invalid */

static BOOLEAN invalidAttributePresent( const ATTRIBUTE_LIST *attributeListPtr,
										const CRYPT_ATTRIBUTE_TYPE attributeType,
										const BOOLEAN isIssuer,
										CRYPT_ATTRIBUTE_TYPE *errorLocus, 
										CRYPT_ERRTYPE_TYPE *errorType )
	{
	BOOLEAN attributePresent;

	/* In some cases only a particular field of an attribute is invalid 
	   rather than the entire attribute.  We use a per-field check if this 
	   is the case (the specific exclusion of path-length constraints in
	   basicConstraints was introduced in RFC 3280) */
	if( attributeType == CRYPT_CERTINFO_PATHLENCONSTRAINT )
		attributePresent = \
				findAttributeField( attributeListPtr,
									CRYPT_CERTINFO_PATHLENCONSTRAINT, 
									CRYPT_ATTRIBUTE_NONE ) != NULL ? \
				TRUE : FALSE;
	else
		attributePresent = \
				checkAttributePresent( attributeListPtr, 
									   CRYPT_CERTINFO_NAMECONSTRAINTS );
	if( attributePresent )
		{
		setErrorValues( CRYPT_CERTINFO_CA, isIssuer ? \
							CRYPT_ERRTYPE_ISSUERCONSTRAINT : \
							CRYPT_ERRTYPE_CONSTRAINT );
		}
	return( attributePresent );
	}

static BOOLEAN invalidAttributesPresent( const ATTRIBUTE_LIST *attibuteListPtr,
										 const BOOLEAN isIssuer,
										 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
										 CRYPT_ERRTYPE_TYPE *errorType )
	{
	return( invalidAttributePresent( attibuteListPtr,
									 CRYPT_CERTINFO_NAMECONSTRAINTS,
									 FALSE, errorLocus, errorType ) || \
			invalidAttributePresent( attibuteListPtr,
									 CRYPT_CERTINFO_POLICYCONSTRAINTS,
									 FALSE, errorLocus, errorType ) || \
			invalidAttributePresent( attibuteListPtr,
									 CRYPT_CERTINFO_INHIBITANYPOLICY,
									 FALSE, errorLocus, errorType ) || \
			invalidAttributePresent( attibuteListPtr,
									 CRYPT_CERTINFO_POLICYMAPPINGS,
									 FALSE, errorLocus, errorType ) || \
			invalidAttributePresent( attibuteListPtr,
									 CRYPT_CERTINFO_PATHLENCONSTRAINT,
									 FALSE, errorLocus, errorType ) ? \
			TRUE : FALSE );
	}

/* Check whether a cert is a PKIX path-kludge cert, which allows extra certs 
   to be kludged into the path without violating any constraints */

static BOOLEAN isPathKludge( const CERT_INFO *certInfoPtr )
	{
	const ATTRIBUTE_LIST *attributeListPtr;

	/* Perform a quick-reject check for certs that haven't been identified 
	   by the cert chain processing code as path-kludge certs */
	if( !( certInfoPtr->flags & CERT_FLAG_PATHKLUDGE ) )
		return( FALSE );

	/* Only CA path-kludge certs are exempt from constraint enforcement.  
	   Non-CA path kludges shouldn't ever occur, but who knows what other 
	   weirdness future RFCs will dream up, so we perform an explicit check 
	   here */
	attributeListPtr = findAttributeField( certInfoPtr->attributes, 
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	return( ( attributeListPtr != NULL && attributeListPtr->intValue ) ? \
			TRUE : FALSE );
	}

/****************************************************************************
*																			*
*							Name Comparison Routines						*
*																			*
****************************************************************************/

/* Perform a wildcarded compare of two strings in attributes.  Certificates
   don't use standard ? and * regular-expression wildcards but instead 
   specify the constraint as a form of longest-suffix filter that's applied 
   to the string (with the usual pile of special-case exceptions that apply 
   to any cert-related rules), so that e.g. www.foo.com would be constrained 
   using foo.com (or more usually .foo.com to avoid erroneous matches for 
   strings like www.barfoo.com) */

typedef enum {
	MATCH_NONE,		/* No special-case matching rules */
	MATCH_EMAIL,	/* Match using email address mailbox exception */
	MATCH_URI,		/* Match only DNS name portion of URI */
	MATCH_LAST		/* Last valid match rule type */
	} MATCH_TYPE;

static BOOLEAN wildcardMatch( const ATTRIBUTE_LIST *constrainedAttribute,
							  const ATTRIBUTE_LIST *attribute,
							  const MATCH_TYPE matchType )
	{
	const char *string = attribute->value;
	const char *constrainedString = constrainedAttribute->value;
	const BOOLEAN isWildcardMatch = ( *string == '.' ) ? TRUE : FALSE;
	int startPos;

	/* Determine the start position of the constraining string within the
	   constrained string: 

		xxxxxyyyyy	- Constrained string
			 yyyyy	- Constraining string
			^
			|
		startPos
	   
	   If the constraining string is longer than the constrained string 
	   (making startPos negative), it can never match */
	startPos = constrainedAttribute->valueLength - attribute->valueLength;
	if( startPos < 0 )
		return( FALSE );

	/* Handle special-case match requirements (PKIX section 4.2.1.11) */
	switch( matchType )
		{
		case MATCH_EMAIL:
			/* Email addresses have a special-case requirement where the 
			   absence of a wildcard-match indicator (the leading dot)
			   indicates that the mailbox has to be located directly on the 
			   constraining hostname rather than merely within that domain, 
			   i.e. user@foo.bar.com is a valid match for .bar.com, but not 
			   for bar.com, which would require user@bar.com to match */
			if( !isWildcardMatch && \
				( startPos < 1 || constrainedString[ startPos - 1 ] != '@' ) )
				return( FALSE );
			break;

		case MATCH_URI:
			{
			URL_INFO urlInfo;
			int status;

			/* URIs can contain trailing location information that isn't 
			   regarded as part of the URI for matching purposes, so before 
			   performing the match we have to parse the URL and only use 
			   the DNS name portion */
			status = sNetParseURL( &urlInfo, constrainedString, 
								   constrainedAttribute->valueLength );
			if( cryptStatusError( status ) )
				return( FALSE );

			/* Adjust the constrained string info to contain only the DNS 
			   name portion of the URI */
			constrainedString = urlInfo.host;
			startPos = urlInfo.hostLen - attribute->valueLength;
			if( startPos < 0 )
				return( FALSE );

			/* URIs have a special-case requirement where the absence of a
			   wildcard-match indicator (the leading dot) indicates that the
			   constraining DNS name is for a standalone host and not a 
			   portion of the constrained string's DNS name.  This means
			   that the DNS-name portion of the URI must be an exact match
			   for the constraining string */
			if( !isWildcardMatch && startPos != 0 )
				return( FALSE );
			}
		}

	/* Check whether the constraining string is a suffix of the constrained
	   string.  For DNS name constraints the rule for RFC 3280 became 
	   "adding to the LHS" as for other constraints, in RFC 2459 it was
	   another special case where it had to be a subdomain, as if an 
	   implicit "." was present */
	return( !strCompare( constrainedString + startPos, attribute->value, 
						 attribute->valueLength ) ? TRUE : FALSE );
	}

static BOOLEAN matchAltnameComponent( const ATTRIBUTE_LIST *constrainedAttribute,
									  const ATTRIBUTE_LIST *attribute,
									  const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	/* If the attribute being matched is a DN, use a DN-specific match */
	if( attributeType == CRYPT_CERTINFO_DIRECTORYNAME )
		return( compareDN( constrainedAttribute->value, attribute->value, 
						   TRUE ) );

	/* It's a string name, use a substring match with attribute type-specific
	   special cases */
	return( wildcardMatch( constrainedAttribute, attribute, 
						   ( attributeType == CRYPT_CERTINFO_RFC822NAME ) ? \
								MATCH_EMAIL : \
						   ( attributeType == CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER ) ? \
								MATCH_URI : MATCH_NONE ) );
	}

static BOOLEAN checkAltnameConstraints( const ATTRIBUTE_LIST *subjectAttributes,
										const ATTRIBUTE_LIST *issuerAttributes,
										const CRYPT_ATTRIBUTE_TYPE attributeType,
										const BOOLEAN isExcluded )
	{
	const ATTRIBUTE_LIST *attributeListPtr, *constrainedAttributeListPtr;

	/* Check for the presence of constrained or constraining altName 
	   components.  If either are absent, there are no constraints to 
	   apply */
	attributeListPtr = findAttributeField( issuerAttributes,
									isExcluded ? \
										CRYPT_CERTINFO_EXCLUDEDSUBTREES : \
										CRYPT_CERTINFO_PERMITTEDSUBTREES,
									attributeType );
	if( attributeListPtr == NULL )
		return( TRUE );

	for( constrainedAttributeListPtr = \
			findAttributeField( subjectAttributes, 
								CRYPT_CERTINFO_SUBJECTALTNAME, attributeType ); 
		constrainedAttributeListPtr != NULL;
		constrainedAttributeListPtr = \
			findNextFieldInstance( constrainedAttributeListPtr ) )
		{
		const ATTRIBUTE_LIST *attributeListCursor;
		BOOLEAN isMatch = FALSE;

		/* Step through the constraining attributes checking if any match 
		   the constrained attribute.  If it's an excluded subtree then none 
		   can match, if it's a permitted subtree then at least one must 
		   match */
		for( attributeListCursor = attributeListPtr;
			 attributeListCursor != NULL && !isMatch;
			 attributeListCursor = 
				findNextFieldInstance( attributeListCursor ) )
			isMatch = matchAltnameComponent( constrainedAttributeListPtr,
											 attributeListCursor,
											 attributeType );
		if( isExcluded == isMatch )
			return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*						Check for Constraint Violations						*
*																			*
****************************************************************************/

/* Check name constraints placed by an issuer, checked if complianceLevel >=
   CRYPT_COMPLIANCELEVEL_PKIX_FULL */

int checkNameConstraints( const CERT_INFO *subjectCertInfoPtr,
						  const ATTRIBUTE_LIST *issuerAttributes,
						  const BOOLEAN isExcluded,
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_LIST *subjectAttributes = subjectCertInfoPtr->attributes;
	const CRYPT_ATTRIBUTE_TYPE constraintType = isExcluded ? \
		CRYPT_CERTINFO_EXCLUDEDSUBTREES : CRYPT_CERTINFO_PERMITTEDSUBTREES;
	ATTRIBUTE_LIST *attributeListPtr;
	BOOLEAN isMatch = FALSE;

	assert( isReadPtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerAttributes, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* If this is a PKIX path-kludge CA cert, the name constraints don't 
	   apply to it (PKIX section 4.2.1.11).  This is required in order to 
	   allow extra certs to be kludged into the path without violating the 
	   constraint.  For example with the chain:

		Issuer	Subject		Constraint
		------	-------		----------
		Root	CA			permitted = "EE"
		CA'		CA'
		CA		EE

	   the kludge cert CA' must be excluded from name constraint 
	   restrictions in order for the path to be valid.  Obviously this is 
	   only necessary for constraints set by the immediate parent, but PKIX 
	   says it's for constraints set by all certs in the chain (!!), thus 
	   making the pathkludge cert exempt from any name constraints, not just 
	   the one that would cause problems */
	if( isPathKludge( subjectCertInfoPtr ) )
		return( CRYPT_OK );

	/* Check the subject DN if constraints exist.  If it's an excluded 
	   subtree then none can match, if it's a permitted subtree then at 
	   least one must match */
	attributeListPtr = findAttributeField( issuerAttributes, constraintType, 
										   CRYPT_CERTINFO_DIRECTORYNAME );
	if( attributeListPtr != NULL )
		{
		while( attributeListPtr != NULL && !isMatch )
			{
			isMatch = compareDN( subjectCertInfoPtr->subjectName,
								 attributeListPtr->value, TRUE );
			attributeListPtr = findNextFieldInstance( attributeListPtr );
			}
		if( isExcluded == isMatch )
			{
			setErrorValues( CRYPT_CERTINFO_SUBJECTNAME, 
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* DN constraints apply to both the main subject DN and any other DNs 
	   that may be present as subject altNames, so after we've checked the 
	   main DN we check any altName DNs as well */
	if( !checkAltnameConstraints( subjectAttributes, issuerAttributes,
								  CRYPT_CERTINFO_DIRECTORYNAME, isExcluded ) )
		{
		setErrorValues( CRYPT_CERTINFO_SUBJECTALTNAME, 
						CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* Compare the Internet-related names if constraints exist.  We don't
	   have to check for the special case of an email address in the DN 
	   since the cert import code transparently maps this to the 
	   appropriate altName component */
	if( !checkAltnameConstraints( subjectAttributes, issuerAttributes,
								  CRYPT_CERTINFO_RFC822NAME, isExcluded ) || \
		!checkAltnameConstraints( subjectAttributes, issuerAttributes,
								  CRYPT_CERTINFO_DNSNAME, isExcluded ) || \
		!checkAltnameConstraints( subjectAttributes, issuerAttributes,
								  CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, 
								  isExcluded ) )
		{
		setErrorValues( CRYPT_CERTINFO_SUBJECTALTNAME, 
						CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	return( CRYPT_OK );
	}

/* Check policy constraints placed by an issuer, checked if complianceLevel 
   >= CRYPT_COMPLIANCELEVEL_PKIX_FULL */

int checkPolicyConstraints( const CERT_INFO *subjectCertInfoPtr,
							const ATTRIBUTE_LIST *issuerAttributes,
							const POLICY_TYPE policyType,
							CRYPT_ATTRIBUTE_TYPE *errorLocus, 
							CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_LIST *attributeListPtr = \
					findAttributeField( issuerAttributes, 
										CRYPT_CERTINFO_CERTPOLICYID, 
										CRYPT_ATTRIBUTE_NONE );
	const ATTRIBUTE_LIST *constrainedAttributeListPtr = \
					findAttributeField( subjectCertInfoPtr->attributes, 
										CRYPT_CERTINFO_CERTPOLICYID, 
										CRYPT_ATTRIBUTE_NONE );
	ATTRIBUTE_LIST *attributeCursor;
	BOOLEAN subjectHasPolicy, issuerHasPolicy;
	BOOLEAN subjectHasAnyPolicy, issuerHasAnyPolicy;

	assert( isReadPtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerAttributes, sizeof( ATTRIBUTE_LIST ) ) );
	assert( policyType >= POLICY_NONE && policyType < POLICY_LAST );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* If there's a policy mapping present, neither the issuer nor subject
	   domain policies can be the wildcard anyPolicy (PKIX section 
	   4.2.1.6) */
	if( containsAnyPolicy( issuerAttributes, 
						   CRYPT_CERTINFO_ISSUERDOMAINPOLICY ) || \
		containsAnyPolicy( issuerAttributes, 
						   CRYPT_CERTINFO_SUBJECTDOMAINPOLICY ) )
		{
		setErrorValues( CRYPT_CERTINFO_POLICYMAPPINGS, 
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If there's no requirement for a policy and none set, we're done */
	if( policyType == POLICY_NONE && constrainedAttributeListPtr == NULL )
		return( CRYPT_OK );

	/* Check the subject policy */
	if( !checkPolicyType( constrainedAttributeListPtr, &subjectHasPolicy,
						  &subjectHasAnyPolicy, 
						  ( policyType == POLICY_NONE_SPECIFIC || \
							policyType == POLICY_SUBJECT_SPECIFIC || \
							policyType == POLICY_BOTH_SPECIFIC ) ? \
							TRUE : FALSE ) )
		{
		setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, 
						CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If there's no requirement for an issuer policy and none set by the 
	   issuer, we're done */
	if( ( ( policyType == POLICY_SUBJECT ) || \
		  ( policyType == POLICY_SUBJECT_SPECIFIC ) ) && \
		attributeListPtr == NULL )
		return( CRYPT_OK );

	/* Check the subject policy */
	if( !checkPolicyType( attributeListPtr , &issuerHasPolicy,
						  &issuerHasAnyPolicy, 
						  ( policyType == POLICY_BOTH_SPECIFIC ) ? \
							TRUE : FALSE ) )
		{
		setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, 
						CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* Both the issuer and subject have some sort of policy, if either are 
	   anyPolicy wildcards (introduced in RFC 3280 section 4.2.1.5) then 
	   it's considered a match */
	if( subjectHasAnyPolicy || issuerHasAnyPolicy )
		return( CRYPT_OK );

	/* An explicit policy is required, make sure that at least one of the 
	   issuer policies matches at least one of the subject policies.  Note
	   that there's no exception for PKIX path-kludge certs, this is an 
	   error in the RFC, for which the text at this point is unchanged from 
	   RFC 2459.  In fact this contradicts the path-processing pesudocode, 
	   but since that in turn contradicts the main text in a number of 
	   places we take the main text as definitive, not the buggy 
	   pseudocode */
	for( attributeCursor = ( ATTRIBUTE_LIST * ) attributeListPtr; \
		 attributeCursor != NULL; \
		 attributeCursor = findNextFieldInstance( attributeCursor ) )
		{
		ATTRIBUTE_LIST *constrainedAttributeCursor;	

		assert( attributeCursor->fieldID == CRYPT_CERTINFO_CERTPOLICYID );

		for( constrainedAttributeCursor = \
					( ATTRIBUTE_LIST * ) constrainedAttributeListPtr; \
			 constrainedAttributeCursor != NULL; \
			 constrainedAttributeCursor = \
					findNextFieldInstance( constrainedAttributeCursor ) )
			{
			assert( constrainedAttributeCursor->fieldID == \
					CRYPT_CERTINFO_CERTPOLICYID );

			if( attributeCursor->valueLength == \
							constrainedAttributeCursor->valueLength && \
				!memcmp( attributeCursor->value, 
						 constrainedAttributeCursor->value, 
						 attributeCursor->valueLength ) )
				return( CRYPT_OK );
			}
		}

	/* We couldn't find a matching policy, report an error */
	setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, CRYPT_ERRTYPE_CONSTRAINT );
	return( CRYPT_ERROR_INVALID );
	}

/* Check path constraints placed by an issuer, checked if complianceLevel 
   >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL */

int checkPathConstraints( const CERT_INFO *subjectCertInfoPtr,
						  const ATTRIBUTE_LIST *issuerAttributes,
						  const int complianceLevel,
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	assert( isReadPtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerAttributes, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* If this is a PKIX path-kludge cert, the path length constraints don't 
	   apply to it (PKIX section 4.2.1.10).  This is required in order to 
	   allow extra certs to be kludged into the path without violating the 
	   name constraint */
	if( isPathKludge( subjectCertInfoPtr ) )
		return( CRYPT_OK );

	/* If the path length constraint hasn't been triggered yet, we're OK */
	if( issuerAttributes->intValue > 0 )
		return( CRYPT_OK );

	/* The path length constraint is in effect, the next cert down the chain 
	   must be an end-entity cert */
	attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes, 
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && attributeListPtr->intValue )
		{
		setErrorValues( CRYPT_CERTINFO_PATHLENCONSTRAINT,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Check a Certificate	Object						*
*																			*
****************************************************************************/

/* Check the validity of a CRL based on an issuer cert */

static int checkCRL( const CERT_INFO *crlInfoPtr,
					 const CERT_INFO *issuerCertInfoPtr,
					 const int complianceLevel,
					 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					 CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	/* If it's a delta CRL, make sure that the CRL numbers make sense (that 
	   is, that the delta CRL was issued after the full CRL) */
	attributeListPtr = findAttributeField( crlInfoPtr->attributes,
										   CRYPT_CERTINFO_DELTACRLINDICATOR, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		const int deltaCRLindicator = ( int ) attributeListPtr->intValue;

		attributeListPtr = findAttributeField( crlInfoPtr->attributes,
											   CRYPT_CERTINFO_CRLNUMBER, 
											   CRYPT_ATTRIBUTE_NONE  );
		if( attributeListPtr != NULL && \
			attributeListPtr->intValue >= deltaCRLindicator )
			{
			setErrorValues( CRYPT_CERTINFO_DELTACRLINDICATOR,
							CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* If it's a standalone CRL entry used purely as a container for 
	   revocation data, don't try and perform any issuer-based checking */
	if( issuerCertInfoPtr == NULL )
		return( CRYPT_OK );

	/* Make sure that the issuer can sign CRLs and the issuer cert in
	   general is in order */
	return( checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_CA, 
						   CRYPT_KEYUSAGE_CRLSIGN, complianceLevel, 
						   errorLocus, errorType ) );
	}

/* Check the validity of a subject cert based on an issuer cert, with the 
   level of checking performed depending on the complianceLevel setting.  If
   the shortCircuitCheck flag is set (used for cert issuer : subject pairs 
   that may already have been checked) we skip the constant-result checks if 
   the combination has already been checked at this compliance level */

int checkCert( CERT_INFO *subjectCertInfoPtr,
			   const CERT_INFO *issuerCertInfoPtr,
			   const BOOLEAN shortCircuitCheck,
			   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
			   CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_LIST *subjectAttributes = subjectCertInfoPtr->attributes;
	const ATTRIBUTE_LIST *issuerAttributes = \
			( issuerCertInfoPtr != NULL ) ? issuerCertInfoPtr->attributes : NULL;
	const ATTRIBUTE_LIST *attributeListPtr;
	const BOOLEAN subjectSelfSigned = \
					( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) ? \
					TRUE : FALSE;
	BOOLEAN subjectIsCA = FALSE, issuerIsCA = FALSE;
	const time_t currentTime = getTime();
	int complianceLevel, status;

	assert( isReadPtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE  ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Determine how much checking we need to perform.  If this is a 
	   currently-under-construction cert we use the maximum compliance level 
	   to ensure that cryptlib never produces broken certs */
	if( subjectCertInfoPtr->certificate == NULL )
		complianceLevel = CRYPT_COMPLIANCELEVEL_PKIX_FULL;
	else
		{
		status = krnlSendMessage( subjectCertInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &complianceLevel, 
								  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's some form of certificate request or an OCSP object (which 
	   means that it isn't signed by an issuer in the normal sense), there's 
	   nothing to check (yet) */
	switch( subjectCertInfoPtr->type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
		case CRYPT_CERTTYPE_CERTCHAIN:
			/* It's an issuer-signed object, there must be an issuer cert 
			   present */
			assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
			if( subjectCertInfoPtr->flags & CERT_FLAG_CERTCOLLECTION )
				{
				/* Cert collections are pure container objects for which the 
				   base cert object doesn't correspond to an actual cert */
				assert( NOTREACHED );
				return( CRYPT_ERROR_INVALID );
				}
			break;

		case CRYPT_CERTTYPE_CERTREQUEST:
		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* These are merely templates submitted to a CA, there's nothing
			   to check.  For example the template could contain constraints
			   that only make sense once the issuer cert is incorporated 
			   into a chain, or a future-dated validity time, or a CA 
			   keyUsage for which the CA provides the appropriate matching
			   basicConstraints value(s), so we can't really perform much
			   checking here */
			return( CRYPT_OK );

		case CRYPT_CERTTYPE_CRL:
			/* There must be an issuer cert present unless we're checking a 
			   standalone CRL entry that acts purely as a container for 
			   revocation data */
			assert( issuerCertInfoPtr == NULL || \
					isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

			/* CRL checking is handled specially */
			return( checkCRL( subjectCertInfoPtr, issuerCertInfoPtr, 
							  complianceLevel, errorLocus, errorType ) );

		case CRYPT_CERTTYPE_CMS_ATTRIBUTES:
		case CRYPT_CERTTYPE_PKIUSER:
			assert( NOTREACHED );
			return( CRYPT_ERROR_INVALID );

		case CRYPT_CERTTYPE_RTCS_REQUEST:
		case CRYPT_CERTTYPE_RTCS_RESPONSE:
		case CRYPT_CERTTYPE_OCSP_REQUEST:
		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			/* These aren't normal cert types, there's nothing to check - we
			   can't even check the issuer since they're not normally issued 
			   by CAs */
			return( CRYPT_OK );

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_INVALID );
		}

	/* There is one universal case in which a cert is regarded as invalid 
	   and that's when it's explicitly not trusted for the purpose.  We
	   perform the check at this point in oblivious mode to ensure that only 
	   the basic trusted usage gets checked */
	if( issuerCertInfoPtr->cCertCert->trustedUsage != CRYPT_ERROR )
		{
		status = checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_CA, 
								CRYPT_KEYUSAGE_KEYCERTSIGN,
								CRYPT_COMPLIANCELEVEL_OBLIVIOUS, 
								errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			/* There was a problem with the issuer cert, convert the problem 
			   to an issuer constraint */
			*errorType = CRYPT_ERRTYPE_ISSUERCONSTRAINT;
			return( status );
			}
		}

	/* If we're running in oblivious mode, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_REDUCED )
		return( CRYPT_OK );

	/* Check that the validity period is in order.  If we're checking an 
	   existing cert then the start time has to be valid, if we're creating
	   a new cert then it doesn't have to be valid since the cert could be
	   created for use in the future */
	if( currentTime < MIN_TIME_VALUE )
		{
		/* Time is broken, we can't reliably check for expiry times */
		setErrorValues( CRYPT_CERTINFO_VALIDFROM, CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}
	if( subjectCertInfoPtr->startTime >= subjectCertInfoPtr->endTime || \
		( subjectCertInfoPtr->certificate != NULL && \
		  currentTime < subjectCertInfoPtr->startTime ) )
		{
		setErrorValues( CRYPT_CERTINFO_VALIDFROM, CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}
	if( currentTime > subjectCertInfoPtr->endTime )
		{
		setErrorValues( CRYPT_CERTINFO_VALIDTO, CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If it's a self-signed cert or if we're doing a short-circuit check of 
	   a cert in a chain that's already been checked, and we've already 
	   checked it at the appropriate level, there's no need to perform any 
	   further checks */
	if( ( subjectSelfSigned || shortCircuitCheck ) && \
		( subjectCertInfoPtr->cCertCert->maxCheckLevel >= complianceLevel ) )
		return( CRYPT_OK );

	/* If the cert isn't self-signed, check name chaining */
	if( !subjectSelfSigned )
		{
		/* Check that the subject issuer name and issuer subject name chain
		   properly.  If the DNs are present in pre-encoded form, we do
		   a binary comparison, which is faster than calling compareDN() */
		if( subjectCertInfoPtr->certificate != NULL )
			{
			if( subjectCertInfoPtr->issuerDNsize != \
									issuerCertInfoPtr->subjectDNsize || \
				memcmp( subjectCertInfoPtr->issuerDNptr, 
						issuerCertInfoPtr->subjectDNptr, 
						subjectCertInfoPtr->issuerDNsize ) )
				{
				setErrorValues( CRYPT_CERTINFO_ISSUERNAME, 
								CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
			}
		else
			if( !compareDN( subjectCertInfoPtr->issuerName,
							issuerCertInfoPtr->subjectName, FALSE ) )
				{
				setErrorValues( CRYPT_CERTINFO_ISSUERNAME, 
								CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
		}

	/* Determine whether the subject or issuer are CA certs */
	attributeListPtr = findAttributeField( subjectAttributes, 
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		subjectIsCA = attributeListPtr->intValue;
	attributeListPtr = findAttributeField( issuerAttributes,
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		issuerIsCA = attributeListPtr->intValue;

	/* If we're doing a reduced level of checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_STANDARD )
		{
		if( subjectCertInfoPtr->cCertCert->maxCheckLevel < complianceLevel )
			subjectCertInfoPtr->cCertCert->maxCheckLevel = complianceLevel;
		return( CRYPT_OK );
		}

	/* Check that the cert usage flags are present and consistent.  The key 
	   usage checking level ranges up to CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL 
	   so we re-do the check even if it's already been done at a lower 
	   level */
	if( subjectCertInfoPtr->cCertCert->maxCheckLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL && \
		subjectCertInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		status = checkKeyUsage( subjectCertInfoPtr, CHECKKEY_FLAG_NONE, 
								CRYPT_UNUSED, complianceLevel, 
								errorLocus, errorType );
		if( cryptStatusError( status ) )
			return( status );
        }

	/* If the cert isn't self-signed, check that issuer is a CA */
	if( !subjectSelfSigned )
		{
		status = checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_CA, 
								CRYPT_KEYUSAGE_KEYCERTSIGN, complianceLevel, 
								errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			/* There was a problem with the issuer cert, convert the problem 
			   to an issuer constraint */
			*errorType = CRYPT_ERRTYPE_ISSUERCONSTRAINT;
			return( status );
			}
		}

	/* Check all the blob (unrecognised) attributes to see if any are marked 
	   critical.  We only do this if it's an existing cert that we've
	   imported rather than one that we've just created, since applying this 
	   check to the latter would make it impossible to create certs with
	   unrecognised critical extensions */
	if( subjectCertInfoPtr->certificate != NULL )
		{
		for( attributeListPtr = subjectAttributes; \
			 attributeListPtr != NULL && !isBlobAttribute( attributeListPtr ); \
			 attributeListPtr = attributeListPtr->next );
		while( attributeListPtr != NULL )
			{
			/* If we've found an unrecognised critical extension, reject the 
			   cert (PKIX section 4.2).  The one exception to this is if the
			   attribute was recognised but has been ignored at this 
			   compliance level, in which case it's treated as a blob
			   attribute */
			if( ( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) && \
				!( attributeListPtr->flags & ATTR_FLAG_IGNORED ) )
				{
				setErrorValues( CRYPT_ATTRIBUTE_NONE, 
								CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
			attributeListPtr = attributeListPtr->next;
			}
		}

	/* If we're not doing at least partial PKIX checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		{
		if( subjectCertInfoPtr->cCertCert->maxCheckLevel < complianceLevel )
			subjectCertInfoPtr->cCertCert->maxCheckLevel = complianceLevel;
		return( CRYPT_OK );
		}

	/* Constraints can only be present in CA certs.  The issuer may not be 
	   a proper CA if it's a self-signed end entity cert or an X.509v1 CA 
	   cert, which is why we also check for !issuerIsCA */
	if( !subjectIsCA && invalidAttributesPresent( subjectAttributes, FALSE, 
												  errorLocus, errorType ) )
		return( CRYPT_ERROR_INVALID );
	if( !issuerIsCA && invalidAttributesPresent( subjectAttributes, TRUE, 
												 errorLocus, errorType ) )
		return( CRYPT_ERROR_INVALID );

	/*  From this point onwards if we're doing a short-circuit check of 
	    certs in a chain we don't apply constraint checks.  This is because 
		the cert-chain code has already performed far more complete checks 
		of the various constraints set by all the certs in the chain rather 
		than just the current cert issuer : subject pair */

	/* If there's a path length constraint present, apply it */
	attributeListPtr = findAttributeField( issuerAttributes,
										   CRYPT_CERTINFO_PATHLENCONSTRAINT, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && !shortCircuitCheck )
		{
		status = checkPathConstraints( subjectCertInfoPtr, attributeListPtr,
									   complianceLevel, errorLocus, 
									   errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* In order to dig itself out of a hole caused by a circular definition, 
	   RFC 3280 added a new extKeyUsage anyExtendedKeyUsage (rather than the
	   more obvious fix of removing the problematic definition).  
	   Unfortunately this causes more problems than it solves because the exact
	   semantics of this new usage aren't precisely defined.  To fix this 
	   problem we invent some plausible ones ourselves: If the only eKU is 
	   anyKU, we treat the overall extKeyUsage as empty, i.e. there are no
	   particular restrictions on usage.  If any other usage is present the 
	   extension has become self-contradictory, so we treat the anyKU as
	   being absent.  See the comment for getExtendedKeyUsageFlags() for how
	   this is handled */
	attributeListPtr = findAttributeField( subjectAttributes,
										   CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && \
		( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) )
		{
		/* If anyKU is present the extension must be non-critical 
		   (PKIX section 4.2.1.13) */
		setErrorValues( CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE, 
						CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If we're not doing full PKIX checking, we're done.  In addition since 
	   all of the remaining checks are constraint checks we can exit at this
	   point if we're doing a short-circuit check */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_FULL || \
		shortCircuitCheck )
		{
		if( subjectCertInfoPtr->cCertCert->maxCheckLevel < complianceLevel )
			subjectCertInfoPtr->cCertCert->maxCheckLevel = complianceLevel;
		return( CRYPT_OK );
		}

	/* If the issuing cert has name constraints and isn't self-signed, make 
	   sure that the subject name and altName falls within the constrained 
	   subtrees.  Since excluded subtrees override permitted subtrees, we 
	   check these first */
	if( !subjectSelfSigned )
		{
		attributeListPtr = findAttributeField( issuerAttributes, 
											   CRYPT_CERTINFO_EXCLUDEDSUBTREES,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && \
			cryptStatusError( \
				checkNameConstraints( subjectCertInfoPtr, attributeListPtr, 
									  TRUE, errorLocus, errorType ) ) )
			return( CRYPT_ERROR_INVALID );
		attributeListPtr = findAttributeField( issuerAttributes, 
											   CRYPT_CERTINFO_PERMITTEDSUBTREES,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && \
			cryptStatusError( \
				checkNameConstraints( subjectCertInfoPtr, attributeListPtr, 
									  FALSE, errorLocus, errorType ) ) )
			return( CRYPT_ERROR_INVALID );
		}

	/* If there's a policy constraint present and the skip count is set to 
	   zero (i.e. the constraint applies to the current cert), check the 
	   issuer constraints against the subject */
	attributeListPtr = findAttributeField( issuerAttributes,
										   CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && attributeListPtr->intValue <= 0 )
		{
		POLICY_TYPE policyType = POLICY_SUBJECT;

		/* Check whether use of the the wildcard anyPolicy has been 
		   disallowed */
		attributeListPtr = findAttribute( issuerCertInfoPtr->attributes, \
										  CRYPT_CERTINFO_INHIBITANYPOLICY, 
										  TRUE );
		if( attributeListPtr != NULL && attributeListPtr->intValue <= 0 )
			policyType = POLICY_SUBJECT_SPECIFIC;

		/* Apply the appropriate policy constraint */
		status = checkPolicyConstraints( subjectCertInfoPtr,
										 issuerAttributes, policyType,
										 errorLocus, errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	if( subjectCertInfoPtr->cCertCert->maxCheckLevel < complianceLevel )
		subjectCertInfoPtr->cCertCert->maxCheckLevel = complianceLevel;
	return( CRYPT_OK );
	}
