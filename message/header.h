// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HEADER_H
#define HEADER_H

#include "list.h"
#include "field.h"

class String;
class Address;
class ContentType;
class ContentTransferEncoding;
class ContentDisposition;
class ContentLanguage;
class Date;


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
    ContentLanguage * contentLanguage() const;
    String contentDescription() const;
    String contentLocation() const;

    List<Address> * addresses( HeaderField::Type ) const;

    HeaderField * field( HeaderField::Type, uint=0 ) const;
    String mimeFields() const;

    void simplify();

    void removeField( HeaderField::Type );

    List<HeaderField> * fields() const;

    String asText() const;

private:
    void verify() const;
    void appendField( String &, HeaderField::Type ) const;

private:
    class HeaderData * d;
};


#endif
