/****************************************************************************
*																			*
*			Certificate Attribute Handling Structures and Prototypes 		*
*						Copyright Peter Gutmann 1997-2005					*
*																			*
****************************************************************************/

#ifndef _CERTATTR_DEFINED

#define _CERTATTR_DEFINED

/* The attribute type information.  This is used to both check the validity
   of encoded attribute data and to describe the structure of an attribute
   when encoding it.  The flags are broken down into the following groups:

	Attribute-specific flags that apply to an individual field or an
	overall attribute.

	SET/SEQUENCE control flags that indicate the end of a SET/SEQUENCE or
	nested SET/SEQUENCE.  These are only used for encoding, for decoding the 
	decoder maintains a parse state stack driver by the encoded data 
	(actually that's not quite correct, when skipping to the end of some 
	SEQUENCEs containing type-and-value pairs we also use the flags to locate 
	the end of the SEQUENCE encoding/start of the next type-and-value entry).  
	The rule for the FL_SEQEND values is that the last one must return the 
	nesting depth to 1, with the outer SEQUENCE being implicit.  In other 
	words a SEQUENCE OF SEQUENCE {} would have a FL_SEQEND value of 1; a 
	SEQUENCE OF GeneralName would have no FL_SEQEND value 

	Decoding level flags that indicate the compliance level at which this
	attribute is decoded.

	The object subtypes for which an attribute is valid.  CRLs actually 
	contain two sets of extensions, one for the entire CRL (crlExtensions) 
	and the other for each entry in the CRL (crlEntryExtension).  Sorting 
	out whether we're adding a CRL extension or per-entry extension is 
	handled by the higher-level code, which references the CRL attribute 
	list or per-entry attribute list as appropriate.

   The attribute flags are:

	FL_OPTIONAL: The field is optional.
	
	FL_DEFAULT: The field has a default value that's set if no field data
		is present.

	FL_EXPLICIT: The field is explicitly tagged, so instead of being en/
		decoded using the tag for the field, it's given a second level of 
		tagging that encapsulated the field's actual tag type.

	FL_IDENTIFIER: Used for the encapsulating SEQUENCE of fields of the type:

		SEQUENCE {
			identifier	OBJECT IDENTIFIER
			data		ANY DEFINED BY identifier
			}

		for which the field identified by a CRYPT_CERTINFO_xxx is the 'data'
		field, and the whole is only encoded if the data field is present.
		The overall item is only encoded if the 'data' field is present.

	FL_SETOF: Applied to the encapsulating SET/SEQUENCE of a SET OF x/
		SEQUENCE OF x to indicate that one or more inner fields may be 
		present.  The field marked with FL_SETOF in the encoding/decoding
		table is bookmarked, if all of the SET/SEQUENCE data isn't read the 
		first time through the decoding table position is restarted from the 
		bookmark until the SET/SEQUENCE data is exhausted.

	FL_NONEMPTY: Used for optional elements of a SET/SEQUENCE to indicate 
		that at least one element must be present.

	FL_NONENCODING: The field is read and written, but not associated with 
		any user data.  This is used for fields such as version numbers that 
		aren't used for encoding user-supplied data but that must be read and 
		written when processing an attribute 

	FL_MULTIVALUED: If a cryptlib-level attribute is part of a SET OF x/
		SEQUENCE OF x, this flag is set to indicate that more than one 
		instance can exist at the same time.  If this flag isn't set, 
		cryptlib will detect that an attribute of that type already exists 
		and refuse to allow a second instance to be added.

	FL_NOCOPY: The attribute is regarded as sensitive and therefore 
		shouldn't be copied from source to destination (e.g. from a cert 
		request into a cert) when the other attributes are copied.
    
	FL_CRITICAL: The overall extension is marked critical when encoding.

	FL_MORE: Another field in the current extension follows.  The last field
		in the extension has FL_MORE clear */

#define FL_SEQEND			0x0000001	/* End of constructed object */
#define FL_SEQEND_1			0x0000001	/*  End of cons.obj, one nesting lvl.*/
#define FL_SEQEND_2			0x0000002	/*  End of cons.obj, two nesting lvl.*/
#define FL_SEQEND_3			0x0000003	/*  End of cons.obj, three nesting lvls.*/
#define FL_SEQEND_MASK		0x0000003	/* Mask for sequence control value */

#define FL_LEVEL_OBLIVIOUS	0x0000000	/* Process at oblivious compliance level */
#define FL_LEVEL_REDUCED	0x0000010	/* Process at reduced compliance level */
#define FL_LEVEL_STANDARD	0x0000020	/* Process at standard compliance level */
#define FL_LEVEL_PKIX_PARTIAL 0x0000030	/* Process at partial PKIX compliance level */
#define FL_LEVEL_PKIX_FULL	0x0000040	/* Process at full PKIX compliance level */
#define FL_LEVEL_MASK		0x0000070	/* Mask for compliance level value */

#define FL_VALID_CERT		0x0000100	/* Valid in a cert */
#define FL_VALID_ATTRCERT	0x0000200	/* Valid in an attrib.cert */
#define FL_VALID_CRL		0x0000400	/* Valid in a CRL */
#define FL_VALID_CERTREQ	0x0000800	/* Valid in a cert.request */
#define FL_VALID_REVREQ		0x0001000	/* Valid in a rev.request */
#define FL_VALID_OCSPREQ	0x0001000	/* Valid in an OCSP request */
#define FL_VALID_OCSPRESP	0x0001000	/* Valid in an OCSP response */

#define FL_OPTIONAL			0x0002000	/* Field is optional */
#define FL_DEFAULT			0x0004000	/* Field has default value */
#define FL_EXPLICIT			0x0008000	/* Field is explicitly tagged */
#define FL_IDENTIFIER		0x0010000	/* Following field contains selection OID */
#define FL_SETOF			0x0020000	/* Start of SET/SEQ OF values */
#define FL_NONEMPTY			0x0040000	/* SET/SEQ must contain at least one entry */
#define FL_NONENCODING		0x0080000	/* Field is a non-encoding value */
#define FL_MULTIVALUED		0x0100000	/* Field can occur multiple times */
#define FL_NOCOPY			0x0200000	/* Attr.isn't copied when attrs.copied*/
#define FL_CRITICAL			0x0400000	/* Extension is marked critical */
#define FL_MORE				0x0800000	/* Further entries follow */

/* If a constructed field is nested (for example a SEQUENCE OF SEQUENCE), the
   FL_SEQEND may need to denote multiple levels of unnesting.  This is done
   by using FL_SEQEND_n, the following macro can be used to extract the
   actual level of nesting */

#define decodeNestingLevel( value )		( ( value ) & FL_SEQEND_MASK )

/* In order to be able to process broken certs, we allow for processing them 
   at various levels of standards compliance.  If the current processing 
   level is below that required for the extension, we skip it and treat it as
   a blob extension */

#define decodeComplianceLevel( value ) \
		( ( ( value ) >> 4 ) & ( FL_LEVEL_MASK >> 4 ) )

/* Some fields have an intrinsic value but no explicitly set value (that is,
   their presence communicates the information they are intended to convey,
   but the fields themselves contain no actual data).  This applies for
   fields that contain OIDs that denote certain things (for example cert.
   policies or key usage).  To denote these identifier fields, the field type
   is set to FIELDTYPE_IDENTIFIER (note that we start at -2 rather than -1,
   which is the CRYPT_ERROR value).  When a field of this type is
   encountered, no data value is recorded, but the OID for the field is
   written to the cert when the field is encoded */

#define FIELDTYPE_IDENTIFIER	-2

/* Some fields have no set value (these arise from ANY DEFINED BY
   definitions) or an opaque value (typically fixed parameters for type-and-
   value pairs).  To denote these fields, the field type is set to
   FIELDTYPE_BLOB */

#define FIELDTYPE_BLOB			-3

/* When a field contains a CHOICE, it can contain any one of the CHOICE
   fields, as opposed to a FL_SETOF which can contain any of the fields that
   follow it.  Currently the only CHOICE fields contain OIDs as choices, the
   CHOICE fieldtype indicates that the value is stored in the field itself
   but the encoding is handled via a separate encoding table pointed to by
   extraData that maps the value to an OID */

#define FIELDTYPE_CHOICE		-4

/* Some fields are composite fields that contain complete certificate data
   structures.  To denote these fields, the field type is a special code
   that specifies the type, and the value member contains the handle or the
   data member contains a pointer to the composite object */

#define FIELDTYPE_DN			-5

/* As an extension of the above, some fields are complex enough to require
   complete alternative encoding tables.  The most obvious one is
   GeneralName, but this is also used for some CHOICE types where the value
   selects a particular OID or entry from an alternative encoding table.  In
   this case the extraData member is a pointer to the alternative encoding
   table */

#define FIELDTYPE_SUBTYPED		-6

/* Another variant of FIELDTYPE_DN is one where the field can contain one of
   a number of string types chosen from the ASN.1 string menagerie.  Rather
   than adding a list of the different string types marked as optional to
   the en/decoding tables, we provide a single DisplayString meta-type which
   has a custom decoding routine that makes the appropriate choice */

#define FIELDTYPE_DISPLAYSTRING	-7

/* Usually the field ID for the first field in an entry (the one containing
   the OID) is the overall attribute ID, however there are one or two
   exceptions in which the attribute ID and field ID are the same but are
   given in separate fields (examples of this are the altNames, which have
   a single field ID SUBJECT/ISSUERALTNAME that applies to the attribute as
   a whole, but also to the one and only field in it.

   If this happens, the field ID for the attribute as a whole is given the
   value FIELDID_FOLLOWS to indicate that the actual ID is present at a later
   point (the first field that isn't a FIELDID_FOLLOWS code is treated as
   the attribute ID) */

#define FIELDID_FOLLOWS			-8

typedef struct {
	/* Information on the overall attribute.  These fields are only set
	   for overall attribute definitions */
	const BYTE FAR_BSS *oid;		/* OID for this attribute */

	/* Information on this particular field in the attribute.  The fieldType
	   is the field as defined (e.g. SEQUENCE, INTEGER), the 
	   fieldEncodingType is the field as encoded: 0 if it's the same as the 
	   field type, or the tag if it's a tagged field.  The default tagging 
	   is to use implicit tags (e.g. [ 0 ] IMPLICIT SEQUENCE) with a field of 
	   type fieldType and encoding of type fieldEncodedType.  If FL_EXPLICIT 
	   is set, it's an explicitly tagged field and both fields are used for 
	   the encoding */
	const CRYPT_ATTRIBUTE_TYPE fieldID;	/* Magic ID for this field */
#ifndef NDEBUG
	const char *description;		/* Text description */
#endif /* NDEBUG */
	const int fieldType;			/* ASN.1 tag/type for this field */
	const int fieldEncodedType;		/* ASN.1 tag for field as encoded */

	/* General status information */
	const long flags;				/* Status and information flags */

	/* Information to allow validity checking for this field */
	const int lowRange;				/* Min/max allowed if numeric/boolean */
	const int highRange;			/* Min/max length if string */
	const long defaultValue;		/* Default value if FL_DEFAULT set */

	/* Extra data needed to process this field, either a pointer to an
	   alternative encoding table or a pointer to the validation function to
	   allow extended validity checking */
	const void *extraData;
	} ATTRIBUTE_INFO;

/* When using a debugger that isn't capable of displaying the symbolic name
   for an enumerated type we allocate a text string describing the field 
   which is being processed, this makes it easier to track down the point in
   a certificate where cryptlib finds a problem */

#ifndef NDEBUG
  #define MKDESC( text )		text,
#else
  #define MKDESC( text )
#endif /* NDEBUG */

/* The validation function used to perform additional validation on fields */

typedef int ( *VALIDATION_FUNCTION )( const ATTRIBUTE_LIST *attributeListPtr );

/* Look up an ATTRIBUTE_INFO entry based on an OID */

const ATTRIBUTE_INFO *oidToAttribute( const ATTRIBUTE_TYPE attributeType,
									  const BYTE *oid );

/* Select the appropriate attribute info table for encoding/type checking */

const ATTRIBUTE_INFO *selectAttributeInfo( const ATTRIBUTE_TYPE attributeType );

/* Get the attribute and attributeID for a field ID */

const ATTRIBUTE_INFO *fieldIDToAttribute( const ATTRIBUTE_TYPE attributeType,
										  const CRYPT_ATTRIBUTE_TYPE fieldID, 
										  const CRYPT_ATTRIBUTE_TYPE subFieldID,
										  CRYPT_ATTRIBUTE_TYPE *attributeID );

/* Write an attribute field */

int writeAttributeField( STREAM *stream, ATTRIBUTE_LIST *attributeListPtr,
						 const int complianceLevel );

#endif /* _CERTATTR_DEFINED */
