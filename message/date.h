// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef DATE_H
#define DATE_H

#include "estring.h"


class Date
    : public Garbage
{
public:
    Date();

    void setRfc822( const EString & );
    EString rfc822() const;
    void setCurrentTime();
    void setUnixTime( uint );
    uint unixTime();

    EString imap() const;

    EString isoDate() const;
    EString isoTime() const;
    int offset() const;
    EString isoDateTime() const;
    void setIsoDateTime( const EString & isoDateTime );

    void setDate( uint, uint, uint, uint, uint, uint, int );
    void setDate( uint, const EString &, uint, uint, uint,
                  uint, int );

    uint year() const;
    uint month() const;
    uint day() const;
    uint hour() const;
    uint minute() const;
    uint second() const;
    uint weekday() const;

    bool valid() const;
    void checkHarder();

    void setTimezone( const EString & );
    void setLocalTimezone();

private:
    class DateData * d;
};


#endif
