#ifndef MESSAGE_H
#define MESSAGE_H

#include "string.h"
#include "header.h"
#include "mimefields.h"


class Message {
public:
    Message( const String &, bool );

    bool valid() const;
    String error() const;
    bool strict() const;

    String rfc822() const;

    Header * header() const;

private:
    void parseMultipart( uint, uint, const String &, const String & );
    void parseBodypart( uint, uint, const String &, Header * );
    Header * header( uint &, uint, const String &, Header::Mode );

private:
    class MessageData * d;
};


#endif
