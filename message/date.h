// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DATE_H
#define DATE_H

#include "string.h"


class Date
{
public:
    Date();

    void setRfc822( const String & );
    String rfc822() const;
    void setCurrentTime();
    void setUnixTime( uint );

    String imap() const;

    String isoDate() const;
    String isoTime() const;
    int offset() const;
    void setDate( uint, const String &, uint,
                  uint, uint, uint,
                  int );

    bool valid() const;

private:
    class /* oooh! what a lovely name! */ DateData * d;
};


#endif
