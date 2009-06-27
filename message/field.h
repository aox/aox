// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef FIELD_H
#define FIELD_H

#include "list.h"


class Date;
class EString;
class UString;
class Address;


class HeaderField
    : public Garbage
{
public:
    static HeaderField *create( const EString &, const EString & );
    static HeaderField *assemble( const EString &, const UString & );

    // The contents of this enum must be kept in sync with the data in
    // src/schema/field-names. Furthermore, new entries MUST NEVER
    // be added.
    enum Type {
        From = 1, ResentFrom,
        Sender, ResentSender,
        ReturnPath,
        ReplyTo,
        To, Cc, Bcc, ResentTo, ResentCc, ResentBcc,
        LastAddressField = ResentBcc,
        MessageId, ResentMessageId,
        InReplyTo,
        References,
        Date, OrigDate, ResentDate,
        Subject, Comments, Keywords,
        ContentType, ContentTransferEncoding, ContentDisposition,
        ContentDescription, ContentId,
        MimeVersion,
        Received,
        ContentLanguage, ContentLocation, ContentMd5,
        Other
    };

protected:
    HeaderField( HeaderField::Type );
    virtual ~HeaderField();

public:
    Type type() const;

    EString name() const;
    void setName( const EString & );

    virtual EString rfc822() const;

    virtual UString value() const;
    void setValue( const UString & );

    EString unparsedValue() const;
    void setUnparsedValue( const EString & );

    void setPosition( uint );
    uint position() const;

    bool valid() const;
    EString error() const;
    void setError( const EString & );

    virtual void parse( const EString & );

    static const char *fieldName( HeaderField::Type );
    static uint fieldType( const EString & );

    EString wrap( const EString & ) const;

    static EString encodeWord( const UString & );
    static EString encodeText( const UString & );
    static EString encodePhrase( const UString & );

private:
    static HeaderField *fieldNamed( const EString & );
    class HeaderFieldData *d;

    void parseText( const EString & );
    void parseOther( const EString & );
    void parseMimeVersion( const EString & );
    void parseContentLocation( const EString & );
    void parseContentBase( const EString & );
};


#endif
