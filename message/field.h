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
    HeaderField( const String &, const String & );

    // The contents of this enum must be kept in sync with the data in
    // src/schema/field-names. Furthermore, new entries MUST be added
    // only at the end.
    enum Type {
        From = 1, ResentFrom,
        Sender, ResentSender,
        ReturnPath,
        ReplyTo,
        To, Cc, Bcc, ResentTo, ResentCc, ResentBcc,
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

    Type type() const;

    String name() const;
    String value() const;

    bool valid() const;
    String error() const;

    List<Address> * parseMailboxList();
    List<Address> * parseMailbox();
    List<Address> * parseAddressList();
    List<Address> * parseMessageId();
    List<Address> * parseReferences();
    ::Date * parseDate();
    ::ContentType * parseContentType();
    ::ContentTransferEncoding * parseContentTransferEncoding();
    ::ContentDisposition * parseContentDisposition();
    ::ContentLanguage * parseContentLanguage();
    String parseContentLocation();
    void parseMimeVersion();

    static const char *fieldName( HeaderField::Type );

private:
    class HeaderFieldData * d;
};


#endif
