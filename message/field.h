// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FIELD_H
#define FIELD_H

#include "list.h"


class Date;
class String;
class Address;


class HeaderField
    : public Garbage
{
public:
    static HeaderField *create( const String &, const String & );
    static HeaderField *assemble( const String &, const String & );

    // The contents of this enum must be kept in sync with the data in
    // src/schema/field-names. Furthermore, new entries MUST be added
    // only at the end.
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

    String name() const;
    void setName( const String & );

    virtual String value();

    virtual String data();
    void setData( const String & );

    bool valid() const;
    bool parsed() const;
    String error() const;
    void setError( const String & );

    virtual void parse( const String & );
    virtual void reassemble( const String & );

    static const char *fieldName( HeaderField::Type );
    static uint fieldType( const String & );

    static String encode( const String & );
    static String unwrap( const String & );
    String wrap( const String & );

private:
    static HeaderField *fieldNamed( const String & );
    class HeaderFieldData *d;
    void setValue( const String & );

    void parseText( const String & );
    void parseOther( const String & );
    void parseMimeVersion( const String & );
    void parseContentLocation( const String & );
};


#endif
