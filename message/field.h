// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FIELD_H
#define FIELD_H

#include "list.h"


class String;
class Address;
class ContentType;
class ContentTransferEncoding;
class ContentDisposition;
class ContentLanguage;
class Date;


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
    String data() const;
    String value() const;

    bool valid() const;
    String error() const;

    bool isMime() const;

    ::Date *date() const;
    List< ::Address > *addresses() const;
    ::ContentType *contentType() const;
    ::ContentTransferEncoding *contentTransferEncoding() const;
    ::ContentDisposition *contentDisposition() const;
    ::ContentLanguage *contentLanguage() const;

    static const char *fieldName( HeaderField::Type );

private:
    class HeaderFieldData *d;

    void setName( const String & );
    void setData( const String & );
    void setValue( const String & );
    void setError( const String & );
    void setString( const String & );

    void parse();
    void parseText();
    void parseMailboxList();
    void parseMailbox();
    void parseAddressList();
    void parseMessageId();
    void parseReferences();
    void parseDate();
    void parseContentType();
    void parseContentTransferEncoding();
    void parseContentDisposition();
    void parseContentLanguage();
    void parseContentLocation();
    void parseMimeVersion();
};


#endif
