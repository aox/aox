/****************************************************************************
*																			*
*					  Certificate Chain Checking Routines					*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

/* This module and chk_cert.c implement the following PKIX checks (* =
   unhandled, see the code comments.  Currently only policy mapping is
   unhandled, this is optional in PKIX and given the nature of the
   kitchenSink extension no-one really knows how to apply it anyway).  For
   simplicity we use the more compact form of RFC 2459 rather than the 18
   page long one from RFC 3280.

	General:

	(a) Verify the basic certificate information:
		(1) The certificate signature is valid.
		(2a) The certificate has not expired.
		(2b) If present, the private key usage period is satisfied.
		(3) The certificate has not been revoked.
		(4a) The subject and issuer name chains correctly.
		(4b) If present, the subjectAltName and issuerAltName chains
			 correctly.

	NameConstraints:

	(b) Verify that the subject name or critical subjectAltName is consistent
		with the constrained subtrees.

	(c) Verify that the subject name or critical subjectAltName is consistent
		with the excluded subtrees.

	Policy Constraints:

	(d) Verify that policy info.is consistent with the initial policy set:
		(1) If the require explicit policy state variable is less than or 
			equal to n, a policy identifier in the certificate must be in 
			the initial policy set.
*		(2) If the policy mapping state variable is less than or equal to n, 
			the policy identifier may not be mapped.
		(3) RFC 3280 addition: If the inhibitAnyPolicy state variable is 
			less than or equal to n, the anyPolicy policy is no longer 
			considered a match (this also extends into (e) and (g) below).

	(e) Verify that policy info.is consistent with the acceptable policy set:
		(1) If the policies extension is marked critical, the policies
			extension must lie within the acceptable policy set.
		(2) The acceptable policy set is assigned the resulting intersection
			as its new value.

	(g) Verify that the intersection of the acceptable policy set and the
		initial policy set is non-null (this is covered by chaining of e(1)).

	Other Constraints:

	(f) Step (f) is missing in the original, it should probably be: Verify 
		that the current path length is less than the path length constraint.  
		If a path length constraint is present in the certificate, update it 
		as for policy constraints in (l).  RFC 3280 addition: If the cert is 
		a PKIX path kludge cert, it doesn't count for path length constraint
		purposes.

	(h) Recognize and process any other critical extension present in the
		certificate.

	(i) Verify that the certificate is a CA certificate.

	Update of state:

	(j) If permittedSubtrees is present in the certificate, set the
		constrained subtrees state variable to the intersection of its
		previous value and the value indicated in the extension field.

	(k) If excludedSubtrees is present in the certificate, set the excluded
		subtrees state variable to the union of its previous value and the
		value indicated in the extension field.

	(l) If a policy constraints extension is included in the certificate,
		modify the explicit policy and policy mapping state variables as
		follows:

		For any of { requireExplicitPolicy, inhibitPolicyMapping, 
		inhibitAnyPolicy }, if the constraint value is present and has value 
		r, the state variable is set to the minimum of (a) its current value 
		and (b) the sum of r and n (the current certificate in the 
		sequence) 

	(m) If a key usage extension is marked critical, ensure that the 
		keyCertSign bit is set */

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
#else
  #include "cert/cert.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in sign.c */

int checkX509signature( const void *signedObject, const int signedObjectLength,
						void **object, int *objectLength, 
						const CRYPT_CONTEXT sigCheckContext,
						const int formatInfo );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Get certificate information for a cert in the chain */

static int getCertInfo( const CERT_INFO *certInfoPtr,
						CERT_INFO **certChainPtr, const int certChainIndex )
	{
	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( certChainIndex >= -2 && \
			certChainIndex < certInfoPtr->cCertCert->chainEnd );

	/* If it's an index into the cert chain, return info for the cert at 
	   that position */
	if( certChainIndex >= 0 && \
		certChainIndex < certInfoPtr->cCertCert->chainEnd )
		return( krnlAcquireObject( certInfoPtr->cCertCert->chain[ certChainIndex ], 
								   OBJECT_TYPE_CERTIFICATE, 
								   ( void ** ) certChainPtr, 
								   CRYPT_ERROR_SIGNALLED ) );

	/* The -1th cert is the leaf itself */
	if( certChainIndex == -1 )
		{
		*certChainPtr = ( CERT_INFO * ) certInfoPtr;
		return( CRYPT_OK );
		}

	/* We've reached the end of the chain */
	*certChainPtr = NULL;
	return( CRYPT_ERROR_NOTFOUND );
	}

/* Find the trust anchor in a cert chain.  The definition of a "trusted 
   cert" is somewhat ambiguous and can have at least two different
   interpretations:

	1. Trust the identified cert in the chain and only verify from there on
	   down.

	2. Trust the root of the chain that contains the identified cert (for 
	   the purposes of verifying that particular chain only) and verify the
	   whole chain.

   Situation 1 is useful where there's a requirement that things go up to an
   external CA somewhere but no-one particularly cares about (or trusts) the
   external CA.  This is probably the most common situation in general PKC 
   usage, in which the external CA requirement is more of an inconvenience
   than anything else.  In this case the end user can choose to trust the
   path at the point where it comes under their control (a local CA or 
   directly trusting the leaf certs) without having to bother about the 
   external CA.

   Situation 2 is useful where there's a requirement to use the full PKI 
   model.  This can be enabled by having the user mark the root CA as
   trusted, although this means that all certs issued by that CA also have
   to be trusted, removing user control over certificate use.  This is 
   required by orthodox PKI theology, followed by all manner of hacks and
   kludges down the chain to limit what can actually be done with the 
   cert(s) */

static int findTrustAnchor( CERT_INFO *certInfoPtr, int *trustAnchorIndexPtr, 
							CRYPT_CERTIFICATE *trustAnchorCertPtr )
	{
	CRYPT_CERTIFICATE iIssuerCert;
	CERT_CERT_INFO *certChainInfo = certInfoPtr->cCertCert;
	SELECTION_STATE savedState;
	int trustAnchorIndex = 0, status;

	/* Clear return value */
	*trustAnchorIndexPtr = CRYPT_ERROR;
	*trustAnchorCertPtr = CRYPT_ERROR;

	/* If the leaf cert is implicitly trusted, exit.  To perform this check 
	   we have to explicitly select the leaf cert by making it appear that 
	   the cert chain is empty.  This is required in order to ensure that we 
	   check the leaf rather than the currently-selected cert */
	saveSelectionState( savedState, certInfoPtr );
	certChainInfo->chainPos = CRYPT_ERROR;
	status = krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_SETATTRIBUTE,
							  &certInfoPtr->objectHandle, 
							  CRYPT_IATTRIBUTE_CERT_CHECKTRUST );
	restoreSelectionState( savedState, certInfoPtr );
	if( cryptStatusOK( status ) )
		/* Indicate that the leaf is trusted and there's nothing further to 
		   do */
		return( OK_SPECIAL );

	/* Walk up the chain looking for a trusted cert.  Note that the 
	   evaluated trust anchor cert position is one past the current cert 
	   position, since we're looking for the issuer of the current cert at
	   position n, which will be located at position n+1.  This means that 
	   it may end up pointing past the end of the chain if the trust anchor 
	   is present in the trust database but not in the chain */
	iIssuerCert = certInfoPtr->objectHandle;
	status = krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_SETATTRIBUTE, 
							  &iIssuerCert, CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER );
	while( cryptStatusError( status ) && \
		   trustAnchorIndex < certChainInfo->chainEnd )
		{
		iIssuerCert = certChainInfo->chain[ trustAnchorIndex++ ];
		status = krnlSendMessage( certInfoPtr->ownerHandle, 
								  IMESSAGE_SETATTRIBUTE, &iIssuerCert, 
								  CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER );
		}
	if( cryptStatusError( status ) || \
		trustAnchorIndex > certChainInfo->chainEnd )
		return( CRYPT_ERROR_NOTFOUND );
	*trustAnchorCertPtr = iIssuerCert;
	*trustAnchorIndexPtr = trustAnchorIndex;

	/* If there are more certs in the chain beyond the one that we stopped 
	   at, check to see whether the next cert is the same as the trust 
	   anchor.  If it is, we use the copy of the cert in the chain rather 
	   than the external one from the trust database */
	if( trustAnchorIndex < certChainInfo->chainEnd - 1 )
		{
		status = krnlSendMessage( certChainInfo->chain[ trustAnchorIndex ],
								  IMESSAGE_COMPARE, &iIssuerCert, 
								  MESSAGE_COMPARE_CERTOBJ );
		if( cryptStatusOK( status ) )
			*trustAnchorCertPtr = certChainInfo->chain[ trustAnchorIndex ];
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Verify a Certificate Chain						*
*																			*
****************************************************************************/

/* Check constraints along a cert chain in certInfoPtr from startCertIndex 
   on down, checked if complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_FULL.  
   There are three types of constraints that can cover multiple certs: path 
   constraints, name constraints, and policy constraints.

   Path constraints are the easiest to check, just make sure that the number 
   of certs from the issuer to the leaf is less than the constraint length, 
   with special handling for PKIX path kludge certs.

   Name constraints are a bit more difficult, the abstract description
   requires building and maintaining a (potentially enormous) name constraint
   tree which is applied to each cert in turn as it's processed, however 
   since name constraints are practically nonexistant and chains are short
   it's more efficient to walk down the cert chain when a constraint is
   encountered and check each cert in turn, which avoids having to maintain
   massive amounts of state information and is no less efficient than a
   single monolithic state comparison.  Again, there's special handling for
   PKIX path kludge certs, see chk_cert.c for details.

   Policy constraints are hardest of all because, with the complex mishmash
   of policies, policy constraints, qualifiers, and mappings it turns out
   that no-one actually knows how to apply them, and even if people could
   agree, with the de facto use of the policy extension as the kitchenSink
   extension it's uncertain how to apply the constraints to typical
   kitchenSink constructs.  The ambiguity of name constraints when applied 
   to altNames is bad enough, with a 50/50 split in PKIX about whether it 
   should be an AND or OR operation, and whether a DN constraint applies to 
   a subjectName or altName or both.  In the absence of any consensus on the
   issue the latter was fixed in the final version of RFC 2459 by somewhat 
   arbitrarily requiring an AND rather than an OR, although how many 
   implementations follow exactly this version rather than the dozen earlier 
   drafts or any other profile or interpretation is unknown.  With policy 
   constraints it's even worse and no-one seems to be able to agree on what 
   to do with them (or more specifically, the people who write the standards 
   don't seem to be aware that there are ambiguities and inconsistencies in 
   the handling of these extensions.  Anyone who doesn't believe this is 
   invited to try implementing the path-processing algorithm in RFC 3280 as 
   described by the pseudocode there).
   
   For example, the various policy constraints in effect act as conditional 
   modifiers on the critical flag of the policies extension and/or the 
   various blah-policy-set settings in the path-processing algorithm, so 
   that under various conditions imposed by the constraints the extension 
   goes from being non-critical to being (effectively) critical.  In addition 
   the constraint extensions can have their own critical flags, which means 
   that we can end up having to chain back through multiple layers of 
   interacting constraint extensions spread across multiple certs to see 
   what the current interpretation of a particular extension is.  Finally, 
   the presence of PKIX path-kludge certs can turn enforcement of constraints
   on and off at various stages of path processing, with extra special cases
   containing exceptions to the exceptions.  In addition the path-kludge
   exceptions apply to some constraint types but not to others, although the
   main body of the spec and the pseudocode path-processing algorithm 
   disagree on which ones and when they're in effect (this implementation
   assumes that the body of the spec is authoritative and the pseudocode
   represents a buggy attempt to implement the spec, rather than the other
   way round).  Since the virtual-criticality can switch itself on and off 
   across certs depending on where in the path they are, the handling of 
   policy constraints is reduced to a complete chaos if we try and interpret 
   them as required by the spec - trying to implement the logic using 
   decision tables ends up with expressions of more than a dozen variables, 
   which indicates that the issue is more or less incomprehensible.  
   However, since it's only applied at the CRYPT_COMPLIANCELEVEL_PKIX_FULL 
   compliance level it's reasonably safe since users should be expecting 
   peculiar behaviour at this level anyway. 

   The requireExplicitPolicy constraint is particularly bizarre, it 
   specifies the number of additional certificates that can be present in 
   the path before the entire path needs to have policies present.  In other 
   words unlike all other length-based constraints (pathLenConstraint, 
   inhibitPolicyMapping, inhibitAnyPolicy) this works both forwards and
   *backwards* up and down the path, making it the PKI equivalent of a COME
   FROM in that at some random point down the path a constraint placed who
   knows where can suddenly retroactively render the previously-valid path 
   invalid.  No-one seems to know why it runs backwards or what the purpose
   of the retroactive triggering after n certs is, for now we only check
   forwards down the path in the manner of all the other length-based 
   constraints.

   Massa make big magic, gunga din */

static int checkConstraints( CERT_INFO *certInfoPtr, const int startCertIndex,
							 const CERT_INFO *issuerCertInfoPtr,
							 int *errorCertIndex, const int explicitPolicy )
	{
	const ATTRIBUTE_LIST *nameConstraintPtr = NULL, *policyConstraintPtr = NULL;
	const ATTRIBUTE_LIST *inhibitPolicyPtr = NULL, *attributeListPtr;
	ATTRIBUTE_LIST pathAttributeList;
	BOOLEAN hasExcludedSubtrees = FALSE, hasPermittedSubtrees = FALSE;
	BOOLEAN hasPolicy = FALSE, hasPathLength = FALSE;
	BOOLEAN hasExplicitPolicy = FALSE, hasInhibitPolicyMap = FALSE;
	BOOLEAN hasInhibitAnyPolicy = FALSE;
	int requireExplicitPolicyLevel, inhibitPolicyMapLevel;
	int inhibitAnyPolicyLevel;
	int certIndex = startCertIndex, status = CRYPT_OK;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( startCertIndex >= -1 );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( certInfoPtr != issuerCertInfoPtr );

	/* Clear return value */
	*errorCertIndex = CRYPT_ERROR;

	/* Check for path constraints */
	attributeListPtr = findAttributeField( issuerCertInfoPtr->attributes,
										   CRYPT_CERTINFO_PATHLENCONSTRAINT, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		memset( &pathAttributeList, 0, sizeof( ATTRIBUTE_LIST ) );
		pathAttributeList.intValue = attributeListPtr->intValue;
		hasPathLength = TRUE;
		}

	/* Check for policy constraints */
	if( explicitPolicy && \
		checkAttributePresent( issuerCertInfoPtr->attributes, 
							   CRYPT_CERTINFO_CERTIFICATEPOLICIES ) )
		/* Policy chaining purely from the presence of a policy extension
		   is only enforced if the explicit-policy option is set */
		hasPolicy = TRUE;
	attributeListPtr = findAttribute( issuerCertInfoPtr->attributes, \
									  CRYPT_CERTINFO_POLICYCONSTRAINTS, FALSE );
	if( attributeListPtr != NULL )
		policyConstraintPtr = attributeListPtr;
	attributeListPtr = findAttribute( issuerCertInfoPtr->attributes, \
									  CRYPT_CERTINFO_INHIBITANYPOLICY, TRUE );
	if( attributeListPtr != NULL )
		inhibitPolicyPtr = attributeListPtr;

	/* Check for name constraints */
	attributeListPtr = findAttribute( issuerCertInfoPtr->attributes, \
									  CRYPT_CERTINFO_NAMECONSTRAINTS, FALSE );
	if( attributeListPtr != NULL )
		{
		nameConstraintPtr = attributeListPtr;
		hasExcludedSubtrees = findAttributeField( nameConstraintPtr, \
												  CRYPT_CERTINFO_EXCLUDEDSUBTREES, 
												  CRYPT_ATTRIBUTE_NONE ) != NULL;
		hasPermittedSubtrees = findAttributeField( nameConstraintPtr, \
												   CRYPT_CERTINFO_PERMITTEDSUBTREES, 
												   CRYPT_ATTRIBUTE_NONE ) != NULL;
		}

	/* If there aren't any critical policies or constraints present (the 
	   most common case), we're done */
	if( !hasPolicy && !hasPathLength && \
		policyConstraintPtr == NULL && inhibitPolicyPtr == NULL && \
		nameConstraintPtr == NULL )
		return( CRYPT_OK );

	/* Check whether there are requireExplicitPolicy, inhibitPolicyMapping, or 
	   inhibitAnyPolicy attributes, which act as conditional modifiers on the
	   criticality and contents of the policies extension */
	attributeListPtr = findAttributeField( policyConstraintPtr,
										   CRYPT_CERTINFO_REQUIREEXPLICITPOLICY, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		requireExplicitPolicyLevel = attributeListPtr->intValue;
		hasExplicitPolicy = TRUE;
		}
	attributeListPtr = findAttributeField( policyConstraintPtr,
										   CRYPT_CERTINFO_INHIBITPOLICYMAPPING, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		inhibitPolicyMapLevel = attributeListPtr->intValue;
		hasInhibitPolicyMap = TRUE;
		}
	if( inhibitPolicyPtr != NULL )
		{
		inhibitAnyPolicyLevel = inhibitPolicyPtr->intValue;
		hasInhibitAnyPolicy = TRUE;
		}

	/* Walk down the chain checking each cert against the issuer */
	for( certIndex = startCertIndex; \
		 cryptStatusOK( status ) && certIndex >= -1; \
		 certIndex-- )
		{
		CERT_INFO *subjectCertInfoPtr;
		POLICY_TYPE policyType;

		/* Get info for the current cert in the chain */
		status = getCertInfo( certInfoPtr, &subjectCertInfoPtr, certIndex );
		if( cryptStatusError( status ) )
			break;

		/* Check for the presence of further policy constraints.  The path 
		   length value can only ever be decremented once set, so if we find 
		   a further value for the length constraint we set the overall 
		   value to the smaller of the two */
		attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
											   CRYPT_CERTINFO_REQUIREEXPLICITPOLICY, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			if( !hasExplicitPolicy || \
				attributeListPtr->intValue < requireExplicitPolicyLevel )
				requireExplicitPolicyLevel = attributeListPtr->intValue;
			hasExplicitPolicy = TRUE;
			}
		attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
											   CRYPT_CERTINFO_INHIBITPOLICYMAPPING, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			if( !hasInhibitPolicyMap || \
				attributeListPtr->intValue < inhibitPolicyMapLevel )
				inhibitPolicyMapLevel = attributeListPtr->intValue;
			hasInhibitPolicyMap = TRUE;
			}
		attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
											   CRYPT_CERTINFO_INHIBITANYPOLICY, 
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			if( !hasInhibitAnyPolicy || \
				attributeListPtr->intValue < inhibitAnyPolicyLevel )
				inhibitAnyPolicyLevel = attributeListPtr->intValue;
			hasInhibitAnyPolicy = TRUE;
			}

		/* If any of the policy constraints have triggered, the policy 
		   extension is now treated as critical even if it wasn't before */
		if( ( hasExplicitPolicy && requireExplicitPolicyLevel <= 0 ) || \
			( hasInhibitAnyPolicy && inhibitAnyPolicyLevel <= 0 ) )
			hasPolicy = TRUE;

		/* Determine the necessary policy check type based on the various
		   policy constraints */
		if( hasPolicy )
			{
			const BOOLEAN inhibitAnyPolicy = \
				( hasInhibitAnyPolicy && inhibitAnyPolicyLevel <= 0 ) ? \
				TRUE : FALSE;

			if( hasExplicitPolicy )
				{
				if( requireExplicitPolicyLevel > 0 )
					policyType = inhibitAnyPolicy ? \
								 POLICY_NONE_SPECIFIC : POLICY_NONE;
				else
				if( requireExplicitPolicyLevel == 0 )
					policyType = inhibitAnyPolicy ? \
								 POLICY_SUBJECT_SPECIFIC : POLICY_SUBJECT;
				else
				if( requireExplicitPolicyLevel < 0 )
					policyType = inhibitAnyPolicy ? \
								 POLICY_BOTH_SPECIFIC : POLICY_BOTH;
				}
			else
				policyType = inhibitAnyPolicy ? \
							 POLICY_NONE_SPECIFIC : POLICY_NONE;
			}

		/* Check that the current cert in the chain obeys the constraints 
		   set by the overall issuer, possibly modified by other certs in
		   the chain */
		if( hasExcludedSubtrees && \
			cryptStatusError( checkNameConstraints( subjectCertInfoPtr,
										nameConstraintPtr, TRUE,
										&subjectCertInfoPtr->errorLocus, 
										&subjectCertInfoPtr->errorType ) ) )
			status = CRYPT_ERROR_INVALID;
		if( cryptStatusOK( status ) && hasPermittedSubtrees && \
			cryptStatusError( checkNameConstraints( subjectCertInfoPtr,
										nameConstraintPtr, FALSE,
										&subjectCertInfoPtr->errorLocus, 
										&subjectCertInfoPtr->errorType ) ) )
			status = CRYPT_ERROR_INVALID;
		if( cryptStatusOK( status ) && hasPolicy && \
			cryptStatusError( checkPolicyConstraints( subjectCertInfoPtr,
										issuerCertInfoPtr->attributes, policyType,
										&subjectCertInfoPtr->errorLocus, 
										&subjectCertInfoPtr->errorType ) ) )
			status = CRYPT_ERROR_INVALID;
		if( cryptStatusOK( status ) && hasPathLength && \
			cryptStatusError( checkPathConstraints( subjectCertInfoPtr,
										&pathAttributeList, 
										CRYPT_COMPLIANCELEVEL_PKIX_FULL,
										&subjectCertInfoPtr->errorLocus, 
										&subjectCertInfoPtr->errorType ) ) )
			status = CRYPT_ERROR_INVALID;
		if( cryptStatusError( status ) )
			/* Remember which cert caused the problem */
			*errorCertIndex = certIndex;

		/* If there are length constraints, decrement them for each cert.  
		   At this point we run into another piece of PKIX weirdness: If
		   there's a path-kludge cert present, it's not counted for path-
		   length constraint purposes, but the exception only holds for path-
		   length constraint purposes, not for require/inhibit policy 
		   constraint purposes.  This is an error in the spec, sections 
		   4.2.1.12 (policy constraints) and 4.2.1.15 (path constraints) 
		   don't permit path-kludge cert exceptions while section 6.1.4(h) 
		   does.  On the other hand given the confusion in the pseudocode 
		   and the fact that it diverges from the body of the spec in other 
		   places as well, we treat it as an error in the (non-
		   authoritative) pseudocode rather than the (authoritative) spec.
		    
		   Unfortunately there's no easy way to tell just from looking at a 
		   cert whether it's one of these kludge certs or not, because it 
		   looks identical to a CA root cert (even the path-building code 
		   has to handle this speculatively, falling back to alternatives 
		   if the initial attempt to construct a path fails).

		   However, for chain-internal kludge certs the chain-assembly code 
		   can determine whether it's a path-kludge by the presence of 
		   further certs higher up in the chain (although it can't tell 
		   whether the chain ends in a path-kludge or a true CA root cert 
		   because they appear identical).  In the case where the chain-
		   assembly code has been able to identify the cert as a path-
		   kludge, we can skip it for path length constraint purposes */
		if( hasPathLength && \
			( !( subjectCertInfoPtr->flags & CERT_FLAG_PATHKLUDGE ) ) )
			pathAttributeList.intValue--;
		if( hasExplicitPolicy )
			requireExplicitPolicyLevel--;
		if( hasInhibitPolicyMap )
			inhibitPolicyMapLevel--;
		if( hasInhibitAnyPolicy )
			inhibitAnyPolicyLevel--;

		/* Release the cert again unless it's the chain cert itself, which
		   is returned by getCertInfo() as the last cert in the chain */
		if( certInfoPtr != subjectCertInfoPtr )
			krnlReleaseObject( subjectCertInfoPtr->objectHandle );
		}

	return( status );
	}

/* Walk down a chain checking each certificate */

int checkCertChain( CERT_INFO *certInfoPtr )
	{
	CRYPT_CERTIFICATE iIssuerCert;
	CERT_CERT_INFO *certChainInfo = certInfoPtr->cCertCert;
	CERT_INFO *issuerCertInfoPtr, *subjectCertInfoPtr;
	BOOLEAN explicitPolicy = TRUE;
	int certIndex, complianceLevel, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Determine how much checking we need to perform */
	status = krnlSendMessage( certInfoPtr->ownerHandle, IMESSAGE_GETATTRIBUTE,
							  &complianceLevel, 
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );
	if( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_FULL )
		{
		int value;

		status = krnlSendMessage( certInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_OPTION_CERT_REQUIREPOLICY );
		if( cryptStatusOK( status ) && !value )
			explicitPolicy = FALSE;
		}

	/* Try and find a trust anchor for the chain */
	status = findTrustAnchor( certInfoPtr, &certIndex, &iIssuerCert );
	if( status == OK_SPECIAL )
		/* The leaf is implicitly trusted, there's nothing more to do */
		return( CRYPT_OK );
	if( cryptStatusError( status ) )
		{
		int value;

		/* We couldn't find a trust anchor, either there's a missing link in 
		   the chain (CRYPT_ERROR_STUART) and it was truncated before we got 
		   to a trusted cert, or it goes to a root cert but it isn't 
		   trusted */
		certChainInfo->chainPos = certChainInfo->chainEnd - 1;
		status = krnlSendMessage( certChainInfo->chain[ certChainInfo->chainEnd - 1 ], 
								  IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_CERTINFO_SELFSIGNED );
		if( cryptStatusOK( status ) && value )
			{
			/* We got a root cert but it's not trusted */
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_TRUSTED_IMPLICIT,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			}
		else
			{
			/* There's a missing link in the chain and it stops at this 
			   cert */
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			}

		return( CRYPT_ERROR_INVALID );
		}
	status = krnlAcquireObject( iIssuerCert, OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &issuerCertInfoPtr, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the trust anchor.  Since this is the start of the chain there 
	   aren't any constraints placed on it by higher-level certs, so all 
	   that we need to check at this point is the cert itself and its 
	   signature if it's self-signed */
	if( certIndex >= certChainInfo->chainEnd )
		{
		CRYPT_ATTRIBUTE_TYPE dummyLocus;
		CRYPT_ERRTYPE_TYPE dummyType;

		/* The issuer cert info is coming from the cert trust database, 
		   don't modify its state when we check it */
		status = checkCert( issuerCertInfoPtr, issuerCertInfoPtr,
							TRUE, &dummyLocus, &dummyType );
		}
	else
		/* The issuer cert is contained in the chain, update its state when
		   we check it */
		status = checkCert( issuerCertInfoPtr, issuerCertInfoPtr,
							TRUE, &issuerCertInfoPtr->errorLocus, 
							&issuerCertInfoPtr->errorType );
	if( cryptStatusOK( status ) && \
		( issuerCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) && \
		issuerCertInfoPtr->iPubkeyContext != CRYPT_ERROR )
		status = checkX509signature( issuerCertInfoPtr->certificate, 
									 issuerCertInfoPtr->certificateSize,
									 NULL, NULL, 
									 issuerCertInfoPtr->iPubkeyContext, 
									 CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		if( certIndex < certChainInfo->chainEnd )
			certChainInfo->chainPos = certIndex;
		return( status );
		}

	/* We've checked the trust anchor, move on to the next cert */
	certIndex--;

	/* Walk down the chain from the trusted cert checking each link in turn */
	while( cryptStatusOK( status ) && certIndex >= -1 && \
		   ( status = getCertInfo( certInfoPtr, &subjectCertInfoPtr,
								   certIndex ) ) == CRYPT_OK )
		{
		/* Check the chaining from issuer to subject (as well as various 
		   other required bits and pieces such as whether the issuer is 
		   really a CA) */
		status = checkCert( subjectCertInfoPtr, issuerCertInfoPtr,
							TRUE, &subjectCertInfoPtr->errorLocus, 
							&subjectCertInfoPtr->errorType );

		/* Check the signature on the subject cert unless it's a data-only
		   cert for which there isn't a context present.  This is OK since
		   the only time that we can have a data-only chain is when we're 
		   reading from an (implicitly trusted) private key store */
		if( cryptStatusOK( status ) && \
			issuerCertInfoPtr->iPubkeyContext != CRYPT_ERROR )
			status = checkX509signature( subjectCertInfoPtr->certificate, 
										 subjectCertInfoPtr->certificateSize,
										 NULL, NULL, 
										 issuerCertInfoPtr->iPubkeyContext, 
										 CRYPT_UNUSED );

		/* Check any constraints that the issuer cert may place on the rest 
		   of the chain */
		if( cryptStatusOK( status ) && \
			complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_FULL )
			{
			int errorCertIndex;

			status = checkConstraints( certInfoPtr, certIndex, 
									   issuerCertInfoPtr, &errorCertIndex,
									   explicitPolicy );
			if( cryptStatusError( status ) )
				certIndex = errorCertIndex;
			}

		/* Move on to the next cert */
		krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		issuerCertInfoPtr = subjectCertInfoPtr;
		certIndex--;
		}

	/* If we stopped before we processed all the certs in the chain, select
	   the one that caused the problem.  We also have to unlock the last 
	   cert that we got to if it wasn't the leaf, which corresponds to the 
	   chain itself */
	if( cryptStatusError( status ) )
		{
		certChainInfo->chainPos = certIndex + 1;
		if( issuerCertInfoPtr != certInfoPtr )
			krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		}

	return( status );
	}
