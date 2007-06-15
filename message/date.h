// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DATE_H
#define DATE_H

#include "string.h"


class Date
    : public Garbage
{
public:
    Date();

    void setRfc822( const String & );
    String rfc822() const;
    void setCurrentTime();
    void setUnixTime( uint );
    uint unixTime();

    String imap() const;

    String isoDate() const;
    String isoTime() const;
    int offset() const;
    String isoDateTime() const;

    void setDate( uint, uint, uint, uint, uint, uint, int );
    void setDate( uint, const String &, uint, uint, uint,
                  uint, int );

    uint year() const;
    uint month() const;
    uint day() const;

    bool valid() const;
    void checkHarder();

private:
    class DateData * d;
};


#endif
