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
class AddressField;
class Date;


class Header {
public:
    enum Mode { Rfc2822, Mime };
    Header( Mode );

    Mode mode() const;
    bool valid() const;
    String error() const;

    void add( HeaderField * );
    void add( const String &, const String & );
    void removeField( HeaderField::Type );

    List< HeaderField > *fields() const;
    HeaderField * field( HeaderField::Type, uint = 0 ) const;
    AddressField * addressField( HeaderField::Type, uint = 0 ) const;

    Date * date( HeaderField::Type = HeaderField::Date ) const;
    String subject() const;
    String inReplyTo() const;
    String messageId( HeaderField::Type = HeaderField::MessageId ) const;
    List< Address > * addresses( HeaderField::Type ) const;
    ContentType * contentType() const;
    ContentTransferEncoding * contentTransferEncoding() const;
    ContentDisposition * contentDisposition() const;
    ContentLanguage * contentLanguage() const;
    String contentDescription() const;
    String contentLocation() const;

    void simplify();

    String asText() const;

private:
    class HeaderData * d;

    void verify() const;
    void appendField( String &, HeaderField * ) const;
};


#endif
