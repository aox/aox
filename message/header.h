#ifndef HEADER_H
#define HEADER_H

#include "string.h"
#include "list.h"

class Address;
class ContentType;
class ContentTransferEncoding;
class ContentDisposition;
class Date;


class HeaderField
{
public:
    HeaderField( const String & name, const String & value );

    String name();
    String value();

    bool valid() const;
    String error() const;

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
        Other // Other must be last
    };

    Type type() const;

    List<Address> * parseMailboxList();
    List<Address> * parseMailbox();
    List<Address> * parseAddressList();
    List<Address> * parseMessageId();
    List<Address> * parseReferences();
    ::Date * parseDate();
    ::ContentType * parseContentType();
    ::ContentTransferEncoding * parseContentTransferEncoding();
    ::ContentDisposition * parseContentDisposition();
    void parseMimeVersion();

private:
    class HeaderFieldData * d;
};


class Header
{
public:
    enum Mode {
        Rfc2822,
        Mime
    };
    Header( Mode );

    void add( const String & name, const String & value );

    Mode mode() const;
    bool valid() const;
    String error() const;

    Date * date( HeaderField::Type = HeaderField::Date ) const;
    String messageId( HeaderField::Type = HeaderField::MessageId ) const;
    String references() const;
    String subject() const;
    String inReplyTo() const;
    ContentType * contentType() const;
    ContentTransferEncoding * contentTransferEncoding() const;
    ContentDisposition * contentDisposition() const;
    String contentDescription() const;

    List<Address> * addresses( HeaderField::Type ) const;

    HeaderField * field( HeaderField::Type, uint=0 ) const;

    void simplify();

    void removeField( HeaderField::Type );

    List<HeaderField> * fields() const;

private:
    void verify() const;

private:
    class HeaderData * d;
};


#endif
