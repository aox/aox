/****************************************************************************
*																			*
*									Keyset ACLs								*
*						Copyright Peter Gutmann 1999-2003					*
*																			*
****************************************************************************/

#ifndef _CRYPTACK_DEFINED

#define _CRYPTACK_DEFINED

/* Key management ACL information.  These work in the same general way as the
   crypto mechanism ACL checks enforced by the kernel.  The ACL entries are:

	Valid keyset types for R/W/D access.
	Valid keyset types for getFirst/Next access.
	Valid keyset types for query access.
	Valid object types to write.
	Valid key management flags in the mechanism info.
	Access type for which an ID parameter is required.
	Access type for which a password (or other aux.info) is required
	[ Specific object types requires for some keyset types ]

  The access-type entries are used for parameter checking and represent all
  access types for which these parameters are required, even if those
  access types aren't currently allowed by the valid access types entry.
  This is to allow them to be enabled by changing only the valid access
  types entry without having to update the other two entries as well.
  
  In addition, there are a few access types (specifically getFirst/Next and
  private key reads) for which the semantics of password/aux info use are
  complex enough that we have to hardcode them, leaving only a 
  representative entry in the ACL definition.  Examples of this are keyset
  vs. crypto device reads (keysets usually need passwords while a logged-
  in device doesn't), speculative reads from the keyset to determine
  presence (which doesn't require a password), and so on.

  The (optional) specific object types entry is required for some keysets
  that require a specific object (typically a certificate or cert chain) 
  rather than just a generic PKC context for the overall keyset item type */

static const FAR_BSS KEYMGMT_ACL keyManagementACL[] = {
	MK_KEYACL( KEYMGMT_ITEM_NONE,			/* No item type */
		/*RWD*/	ST_NONE,
		/*FnQ*/	ST_NONE,
		/*Obj*/	ST_NONE,
		/*Flg*/	KEYMGMT_FLAG_NONE,
		ACCESS_KEYSET_xxxxx, ACCESS_KEYSET_xxxxx ),
	MK_KEYACL_EX( KEYMGMT_ITEM_PUBLICKEY,	/* Access public key */
		/* R */	ST_KEYSET_ANY | ST_DEV_FORT | ST_DEV_P11,
		/* W */	ST_KEYSET_FILE | ST_KEYSET_DBMS | ST_KEYSET_LDAP | ST_DEV_FORT | ST_DEV_P11,
		/* D */	ST_KEYSET_FILE | ST_KEYSET_DBMS | ST_KEYSET_LDAP | ST_DEV_FORT | ST_DEV_P11,
		/* Fn*/	ST_KEYSET_FILE | ST_KEYSET_DBMS | ST_KEYSET_DBMS_STORE | ST_DEV_FORT,
		/* Q */	ST_KEYSET_DBMS | ST_KEYSET_DBMS_STORE | ST_KEYSET_LDAP,
		/*Obj*/	ST_CTX_PKC | ST_CERT_CERT | ST_CERT_CERTCHAIN,
		/*Flg*/	KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_LABEL_ONLY | KEYMGMT_MASK_CERTOPTIONS,
		ACCESS_KEYSET_FxRxD, ACCESS_KEYSET_FNxxx,
		ST_KEYSET_DBMS | ST_KEYSET_DBMS_STORE | ST_KEYSET_LDAP | \
						 ST_DEV_FORT | ST_DEV_P11,
		ST_CERT_CERT | ST_CERT_CERTCHAIN ),
	MK_KEYACL_RWD( KEYMGMT_ITEM_PRIVATEKEY,	/* Access private key */
		/* R */	ST_KEYSET_FILE | ST_KEYSET_FILE_PARTIAL | ST_DEV_FORT | ST_DEV_P11,
		/* W */	ST_KEYSET_FILE | ST_DEV_FORT | ST_DEV_P11,
		/* D */	ST_KEYSET_FILE | ST_DEV_FORT | ST_DEV_P11,
		/*FnQ*/	ST_NONE, ST_NONE,
		/*Obj*/	ST_CTX_PKC,
		/*Flg*/	KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_LABEL_ONLY | KEYMGMT_MASK_USAGEOPTIONS,
		ACCESS_KEYSET_xxRxD, ACCESS_KEYSET_xxXXx ),
	MK_KEYACL( KEYMGMT_ITEM_SECRETKEY,		/* Access secret key */
		/*RWD*/	ST_KEYSET_FILE,
		/*FnQ*/	ST_NONE, 
		/*Obj*/	ST_CTX_CONV,
		/*Flg*/	KEYMGMT_FLAG_NONE,
		ACCESS_KEYSET_xxRxD, ACCESS_KEYSET_xxRWx ),
	MK_KEYACL_RWD( KEYMGMT_ITEM_REQUEST,	/* Access cert request */
		/*RWD*/	ST_KEYSET_DBMS_STORE, ST_KEYSET_DBMS_STORE, ST_NONE,
		/*FnQ*/	ST_NONE, ST_KEYSET_DBMS_STORE,
		/*Obj*/	ST_CERT_CERTREQ | ST_CERT_REQ_CERT | ST_CERT_REQ_REV,
		/*Flg*/	KEYMGMT_FLAG_UPDATE,
		ACCESS_KEYSET_FxRxD, ACCESS_KEYSET_FNxxx ),
	MK_KEYACL_RWD( KEYMGMT_ITEM_PKIUSER,	/* Access PKI user info */
		/*RWD*/	ST_KEYSET_DBMS_STORE, ST_KEYSET_DBMS_STORE, ST_NONE,
		/*FnQ*/	ST_NONE, ST_NONE,
		/*Obj*/	ST_CERT_PKIUSER,
		/*Flg*/	KEYMGMT_FLAG_GETISSUER,
		ACCESS_KEYSET_FxRxD, ACCESS_KEYSET_FNxxx ),
	MK_KEYACL_RWD( KEYMGMT_ITEM_REVOCATIONINFO,	/* Access revocation info/CRL */
		/*RWD*/	ST_KEYSET_DBMS | ST_KEYSET_DBMS_STORE, ST_KEYSET_DBMS, ST_NONE,
		/*FnQ*/	ST_NONE, ST_NONE,
		/*Obj*/	ST_CERT_CRL,
		/*Flg*/	KEYMGMT_FLAG_CHECK_ONLY,
		ACCESS_KEYSET_FxRxD, ACCESS_KEYSET_FNxxx ),
	MK_KEYACL_RWD( KEYMGMT_ITEM_DATA,	/* Other data (for PKCS #15 tokens) */
		/*RWD*/	ST_KEYSET_FILE, ST_KEYSET_FILE, ST_NONE,
		/*FnQ*/	ST_NONE, ST_NONE,
		/*Obj*/	ST_NONE,
		/*Flg*/	KEYMGMT_FLAG_NONE,
		ACCESS_KEYSET_xxRWD, ACCESS_KEYSET_FNxxx ),
	MK_KEYACL( KEYMGMT_ITEM_LAST,		/* Last item type */
		/*RWD*/	ST_NONE,
		/*FnQ*/	ST_NONE,
		/*Obj*/	ST_NONE,
		/*Flg*/	KEYMGMT_FLAG_NONE,
		ACCESS_KEYSET_xxxxx, ACCESS_KEYSET_xxxxx )
	};

/* It's a keyset action message, check the access conditions for the mechanism
   objects */

static int preDispatchCheckKeysetAccess( const int objectHandle,
										 const MESSAGE_TYPE message,
										 const void *messageDataPtr,
										 const int messageValue,
										 const void *dummy )
	{
	const MESSAGE_TYPE localMessage = message & MESSAGE_MASK;
	const MESSAGE_KEYMGMT_INFO *mechanismInfo = \
		  ( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
	const KEYMGMT_ACL *keymgmtACL = \
		  &keyManagementACL[ messageValue ];
	const int accessType = \
			( localMessage == MESSAGE_KEY_GETKEY ) ? ACCESS_FLAG_R : \
			( localMessage == MESSAGE_KEY_SETKEY ) ? ACCESS_FLAG_W : \
			( localMessage == MESSAGE_KEY_DELETEKEY ) ? ACCESS_FLAG_D : \
			( localMessage == MESSAGE_KEY_GETFIRSTCERT ) ? ACCESS_FLAG_F : \
			( localMessage == MESSAGE_KEY_GETNEXTCERT ) ? ACCESS_FLAG_N : 0;
	OBJECT_SUBTYPE subType;
	int paramObjectHandle;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( localMessage == MESSAGE_KEY_GETKEY || \
		 localMessage == MESSAGE_KEY_SETKEY || \
		 localMessage == MESSAGE_KEY_DELETEKEY || \
		 localMessage == MESSAGE_KEY_GETFIRSTCERT || \
		 localMessage == MESSAGE_KEY_GETNEXTCERT );
	PRE( messageDataPtr != NULL );
	PRE( messageValue > KEYMGMT_ITEM_NONE && \
		 messageValue < KEYMGMT_ITEM_LAST );
	PRE( keymgmtACL->itemType == messageValue );
	PRE( accessType != 0 );

	/* Perform a combined check to ensure the item type being accessed is
	   appropriate for this keyset type and the access type is valid */
	subType = objectST( objectHandle );
	switch( localMessage )
		{
		case MESSAGE_KEY_GETKEY:
			if( !isValidSubtype( keymgmtACL->keysetR_subTypeA, subType ) && \
				!isValidSubtype( keymgmtACL->keysetR_subTypeB, subType ) )
				return( CRYPT_ARGERROR_OBJECT );
			break;

		case MESSAGE_KEY_SETKEY:
			if( !isValidSubtype( keymgmtACL->keysetW_subTypeA, subType ) && \
				!isValidSubtype( keymgmtACL->keysetW_subTypeB, subType ) )
				return( CRYPT_ARGERROR_OBJECT );
			break;

		case MESSAGE_KEY_DELETEKEY:
			if( !isValidSubtype( keymgmtACL->keysetD_subTypeA, subType ) && \
				!isValidSubtype( keymgmtACL->keysetD_subTypeB, subType ) )
				return( CRYPT_ARGERROR_OBJECT );
			break;

		case MESSAGE_KEY_GETFIRSTCERT:
		case MESSAGE_KEY_GETNEXTCERT:
			/* The two special-purpose accesses are differentiated by whether
			   there's state information provided.  For a general query the
			   result set is determined by an initially-submitted query
			   which is followed by a sequence of fetches.  For a getFirst/
			   getNext the results are determined by a cert identifier with
			   state held externally in the location pointed to by the
			   auxiliary info pointer */
			if( mechanismInfo->auxInfo == NULL )
				{
				/* Keyset query.  We report this as an arg error since we'll
				   have been passed a CRYPT_KEYID_NONE or empty keyID, this
				   is more sensible than an object error since there's
				   nothing wrong with the object, the problem is that
				   there's no keyID present */
				if( !isValidSubtype( keymgmtACL->keysetQ_subTypeA, subType ) && \
					!isValidSubtype( keymgmtACL->keysetQ_subTypeB, subType ) )
					return( ( mechanismInfo->keyIDtype == CRYPT_KEYID_NONE ) ? \
							CRYPT_ARGERROR_NUM1 : CRYPT_ARGERROR_STR1 );
				}
			else
				{
				/* getFirst/next.  We can report an object error here since
				   this message is only sent internally */
				if( !isValidSubtype( keymgmtACL->keysetFN_subTypeA, subType ) && \
					!isValidSubtype( keymgmtACL->keysetFN_subTypeB, subType ) )
					return( CRYPT_ARGERROR_OBJECT );

				/* Inner precondition: The state information points to an
				   integer value containing a reference to the currently
				   fetched object */
				PRE( mechanismInfo->auxInfo != NULL && \
					 mechanismInfo->auxInfoLength == sizeof( int ) );
				}
			break;

		default:
			assert( NOTREACHED );
		}

	/* Make sure there's ID information present if required */
	if( keymgmtACL->idUseFlags & accessType )
		{
		if( mechanismInfo->keyIDtype == CRYPT_KEYID_NONE )
			return( CRYPT_ARGERROR_NUM1 );
		if( mechanismInfo->keyID == NULL || mechanismInfo->keyIDlength < 1 )
			return( CRYPT_ARGERROR_STR1 );
		}

	/* Make sure there's a password present/not present if required.  We
	   only check for incorrect parameters here if they were supplied by the
	   user, non-user-supplied parameters (which come from within cryptlib)
	   are checked by an assertion later on.  For keyset objects the
	   password is optional on reads since it may be a label-only read or an
	   opportunistic read that tries to read the key without a password
	   initially and falls back to retrying with a password if this fails,
	   for device objects the password is never used since it was supplied
	   when the user logged on to the device.

	   Since the semantics of passwords for private keys are too complex to
	   express with a simple ACL entry, this check is hardcoded */
	if( messageValue == KEYMGMT_ITEM_PRIVATEKEY )
		{
		if( objectTable[ objectHandle ].type == OBJECT_TYPE_KEYSET )
			{
			if( localMessage == MESSAGE_KEY_SETKEY && \
				( mechanismInfo->auxInfo == NULL || \
				  mechanismInfo->auxInfoLength < 1 ) )
				/* Private key writes to a keyset must provide a password */
				return( CRYPT_ARGERROR_STR1 );
			}
		else
			if( ( mechanismInfo->auxInfo != NULL || \
				  mechanismInfo->auxInfoLength != 0 ) )
				/* Private key access to a device doesn't use a password */
				return( ( keymgmtACL->idUseFlags & accessType ) ? \
						CRYPT_ARGERROR_STR2 : CRYPT_ARGERROR_STR1 );
		}

	/* Inner precondition: Only allowed flags are set, there's only one of
	   the usage preference flags set, and the object handle to get/set is
	   not present if not required (the presence and validity check when it
	   is required is performed further down) */
	PRE( !( ~keymgmtACL->allowedFlags & mechanismInfo->flags ) );
	PRE( mechanismInfo->flags >= KEYMGMT_FLAG_NONE && \
		 mechanismInfo->flags < KEYMGMT_FLAG_LAST );
	PRE( ( mechanismInfo->flags & KEYMGMT_MASK_USAGEOPTIONS ) != \
		 KEYMGMT_MASK_USAGEOPTIONS );
	PRE( localMessage == MESSAGE_KEY_SETKEY || \
		 mechanismInfo->cryptHandle == CRYPT_ERROR );

	/* Inner precondition: There's ID information and a password/aux.data
	   present/not present as required.  For a private key read the password
	   is optional so we don't check it, for a getFirst/getNext the aux.data
	   (a pointer to query state) is used when assembling a cert chain (state
	   held in the cert) and not used when performing a general query (state
	   held in the keyset) */
	PRE( ( ( keymgmtACL->idUseFlags & accessType ) && \
		   mechanismInfo->keyIDtype != CRYPT_KEYID_NONE && \
		   mechanismInfo->keyID != NULL && \
		   mechanismInfo->keyIDlength >= 1 ) ||
		 ( !( keymgmtACL->idUseFlags & accessType ) && \
		   mechanismInfo->keyIDtype == CRYPT_KEYID_NONE && \
		   mechanismInfo->keyID == NULL && \
		   mechanismInfo->keyIDlength == 0 ) );
	PRE( ( messageValue == KEYMGMT_ITEM_PRIVATEKEY && \
		   localMessage == MESSAGE_KEY_GETKEY ) ||
		 localMessage == MESSAGE_KEY_GETFIRSTCERT ||
		 localMessage == MESSAGE_KEY_GETNEXTCERT ||
		 ( ( keymgmtACL->pwUseFlags & accessType ) && \
		   mechanismInfo->auxInfo != NULL && \
		   mechanismInfo->auxInfoLength >= 1 ) ||
		 ( !( keymgmtACL->pwUseFlags & accessType ) && \
		   mechanismInfo->auxInfo == NULL && \
		   mechanismInfo->auxInfoLength == 0 ) );

	/* Perform message-type-specific checking of parameters */
	switch( localMessage )
		{
		case MESSAGE_KEY_GETKEY:
			break;

		case MESSAGE_KEY_SETKEY:
			/* Make sure the object being set is valid and its type is
			   appropriate for this key management item (and via previous
			   checks, keyset) type.  Note that this checks for inclusion in 
			   the set of valid objects, in particular a public-key context 
			   can have almost any type of certificate object attached but 
			   will still be regarded as valid since the context meets the 
			   check requirements.  More specific object checks are performed
			   further on */
			paramObjectHandle = mechanismInfo->cryptHandle;
			if( !isValidObject( paramObjectHandle ) || \
				!isSameOwningObject( objectHandle, paramObjectHandle ) )
				return( CRYPT_ARGERROR_NUM1 );
			subType = objectST( paramObjectHandle );
			if( !isValidSubtype( keymgmtACL->objSubTypeA, subType ) && \
				!isValidSubtype( keymgmtACL->objSubTypeB, subType ) )
				{
				/* If we're only allowed to add contexts, this could be a
				   cert object with an associated context, in which case
				   we look for an associated context and try again */
				if( keymgmtACL->objSubTypeA != ST_CTX_PKC )
					return( CRYPT_ARGERROR_NUM1 );
				paramObjectHandle = findTargetType( paramObjectHandle,
													OBJECT_TYPE_CONTEXT );
				if( cryptStatusError( paramObjectHandle ) || \
					objectST( paramObjectHandle ) != ST_CTX_PKC )
					return( CRYPT_ARGERROR_NUM1 );
				}
			if( !isInHighState( paramObjectHandle ) && \
				!( subType == ST_CERT_PKIUSER || subType == ST_CERT_REQ_REV ) )
				/* PKI user info and revocation requests aren't signed.  Like
				   private key password semantics, these are a bit too 
				   complex to express in the ACL so they're hardcoded */
				return( CRYPT_ARGERROR_NUM1 );

			/* If we don't need to perform an specific-object check, we're
			   done */
			subType = objectST( objectHandle );
			if( !isValidSubtype( keymgmtACL->specificKeysetSubTypeA, subType ) && \
				!isValidSubtype( keymgmtACL->specificKeysetSubTypeB, subType ) )
				break;

			/* We need a specific cert type for this keyset, make sure we've
			   been passed this and not just a generic PKC-equivalent
			   object */
			paramObjectHandle = findTargetType( mechanismInfo->cryptHandle,
												OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( paramObjectHandle ) )
				return( CRYPT_ARGERROR_NUM1 );
			subType = objectST( paramObjectHandle );
			if( !isValidSubtype( keymgmtACL->specificObjSubTypeA, subType ) && \
				!isValidSubtype( keymgmtACL->specificObjSubTypeB, subType ) )
				return( CRYPT_ARGERROR_NUM1 );
			if( !isInHighState( paramObjectHandle ) )
				return( CRYPT_ARGERROR_NUM1 );
			break;

		case MESSAGE_KEY_DELETEKEY:
			break;

		case MESSAGE_KEY_GETFIRSTCERT:
			break;

		case MESSAGE_KEY_GETNEXTCERT:
			break;

		default:
			assert( NOTREACHED );
		}

	/* Postcondition: The access and parameters are valid and the object
	   being passed in is of the correct type if present.  We don't
	   explicitly state this since it's just regurgitating the checks
	   already performed above */

	return( CRYPT_OK );
	}
#endif /* _CRYPTACK_DEFINED */
