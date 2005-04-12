// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FIELD_H
#define FIELD_H

#include "list.h"


class Date;
class String;
class Address;


class HeaderField {
public:
    static HeaderField *create( const String &, const String & );

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

public:
    Type type() const;

    String name() const;
    void setName( const String & );

    String string() const;
    void setString( const String & );

    virtual String value() const;
    void setValue( const String & );

    virtual String data() const;
    void setData( const String & );

    bool valid() const;
    String error() const;
    void setError( const String & );

    virtual void parse();

    static const char *fieldName( HeaderField::Type );

private:
    class HeaderFieldData *d;

    void parseText();
    void parseMimeVersion();
    void parseContentLocation();
};


#endif
