// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "date.h"

#include "parser.h"

// time_t
#include <time.h>


class DateData
    : public Garbage
{
public:
    DateData() { reset(); }

    void reset() {
        day =0;
        month = 0;
        year = 0;
        hour = 0;
        minute = 0;
        second = 0;
        tz = 0;
        tzn = "";
        valid = false;
        minus0 = false;
    }

public:
    int day, month, year;
    int hour, minute, second;
    int tz;
    String tzn;
    bool valid;
    bool minus0;
};


/*! \class Date date.h

    The Date class contains a date, with attendant time and timezeone.

    It can parse RFC 822 format dates, as well as encode dates in
    rfc822, imap and ISO-8601 formats. It cannot change itself or
    interact with other dates: This is meant purely as
    parse-and-store class.
*/


/*! Constructs an empty, invalid Date. */

Date::Date()
    : d( new DateData )
{
}


/*! Sets this date to point to the current date, time and timezone. */

void Date::setCurrentTime()
{
    time_t now = ::time(0);
    struct tm gmt = *(::gmtime(&now));
    struct tm local = *(::localtime(&now));
    struct tm conv = *(::localtime(&now));
    signed int diff;

    // if GMT were local, what would it be?
    conv.tm_year = gmt.tm_year;
    conv.tm_mon  = gmt.tm_mon;
    conv.tm_mday = gmt.tm_mday;
    conv.tm_hour = gmt.tm_hour;
    conv.tm_min  = gmt.tm_min;
    conv.tm_sec  = gmt.tm_sec;
    conv.tm_wday = gmt.tm_wday;
    conv.tm_yday = gmt.tm_yday;

    // see how far the real local is from GMT-as-local
    diff = (int)((mktime(&local) - mktime(&conv)) / 60.0);

    d->day = local.tm_mday;
    d->month = local.tm_mon+1;
    d->year = local.tm_year+1900;
    d->hour = local.tm_hour;
    d->minute = local.tm_min;
    d->second = local.tm_sec;
    d->tz = diff;
    d->tzn = "";
    d->valid = true;
    d->minus0 = false;
}


/*! Sets this date to \a t seconds after the start of 1970, give or
    take a few leap seconds. \a t is assumed to be UTC.
*/

void Date::setUnixTime( uint t )
{
    time_t tmp = t;
    struct tm gmt = *(::gmtime(&tmp));

    d->reset();

    d->day = gmt.tm_mday;
    d->month = gmt.tm_mon+1;
    d->year = gmt.tm_year+1900;
    d->hour = gmt.tm_hour;
    d->minute = gmt.tm_min;
    d->second = gmt.tm_sec;
    d->valid = true;
    d->minus0 = false;

}


/*! Returns the unix time corresponding to this data, or 0 if the data
    is invalid.
*/

uint Date::unixTime()
{
    if ( !valid() )
        return 0;

    struct tm t;
    t.tm_mday = d->day;
    t.tm_mon = d->month - 1;
    t.tm_year = d->year - 1900;
    t.tm_hour = d->hour;
    t.tm_min = d->minute;
    t.tm_sec = d->second;
    t.tm_isdst = 0;
    // this uses the nonstandard timegm() instead of wrapping mktime
    // in in logic. I think timegm() is better because it works on the
    // platforms we support, and it actually works. we've had to many
    // timezone-dependent bugs now.
    return timegm( &t ) - d->tz * 60;
}


// list of time zone names that have only one definition, or at least one
// overwhelmingly common one.

static struct {
    const char * name;
    int offset;
} zones[] = {
    // from INN 1.4.
    { "gmt", 0 }, //Greenwich Mean
    { "ut", 0 },  // Universal
    { "utc", 0 }, // Universal Coordinated
    { "cut", 0 }, // Coordinated Universal
    { "z", 0 }, // Greenwich Mean
    { "wet", 0 }, // Western European
    { "bst", +60 }, // British Summer
    { "nst", -210 }, // Newfoundland Standard
    { "ndt", -150 }, // Newfoundland Daylight
    { "ast", -240 }, // Atlantic Standard
    { "adt", -180 }, // Atlantic Daylight
    { "est", -300 }, // Eastern Standard
    { "edt", -240 }, // Eastern Daylight
    { "cst", -360 }, // Central Standard
    { "cdt", -300 }, // Central Daylight
    { "mst", -420 }, // Mountain Standard
    { "mdt", -360 }, // Mountain Daylight
    { "pst", -480 }, // Pacific Standard
    { "pdt", -420 }, // Pacific Daylight
    { "yst", -540 }, // Yukon Standard
    { "ydt", -480 }, // Yukon Daylight
    { "akst", -540 }, // Alaska Standard
    { "akdt", -480 }, // Alaska Daylight
    { "hst", -600 }, // Hawaii Standard
    { "hast", -600 }, // Hawaii-Aleutian Standard
    { "hadt", -540 }, // Hawaii-Aleutian Daylight
    { "ces", 120 }, // Central European Summer
    { "cest", 120 }, // Central European Summer
    { "mez", 60 }, // Middle European
    { "mezt", 120 }, // Middle European Summer
    { "cet", 60 }, // Central European
    { "met", 60 }, // Middle European
    { "eet", 120 }, // Eastern Europe
    { "msk", 180 }, // Moscow Winter
    { "msd", 240 }, // Moscow Summer
    { "wast", 480 }, // West Australian Standard
    { "wadt", 540 }, // West Australian Daylight
    { "hkt", 480 }, // Hong Kong
    { "cct", 480 }, // China Coast
    { "jst", 480 }, // Japan Standard
    { "kst", 540 }, // Korean Standard
    { "kdt", 540 }, // Korean Daylight
    { "cast", 570 }, // Central Australian Standard
    { "cadt", 630 }, // Central Australian Daylight
    { "east", 600 }, // Eastern Australian Standard
    { "eadt", 660 }, // Eastern Australian Daylight
    { "nzst", 720 }, // New Zealand Standard
    { "nzdt", 780 }, // New Zealand Daylight

    // additional unique zone names observed
    { "brt", -180 }, // ?
    { "grnlnddt", -120 }, // greenland daylight savings time?
    { "grnlndst", -180 }, // greenland standard time?
    { "mest", 120 }, // european summer time, by various names
    { "mesz", 120 },
    { "metdst", 120 },
    { "sast", 120 }, // south africa?
    { "sat", 120 }, // south africa?

    // end of the list

    { 0, 0 }
};

static const char * months[] = { "Jan", "Feb", "Mar", "Apr",
                                 "May", "Jun", "Jul", "Aug",
                                 "Sep", "Oct", "Nov", "Dec" };

static const char * weekdays[] = { "Mon", "Tue", "Wed", "Thu",
                                   "Fri", "Sat", "Sun" };

// return 1-12 for january-december, or 0 for error
static uint month( const String & name )
{
    uint n = 0;
    switch ( name[0] ) {
    case 'j': // "jan" "jun" "jul"
    case 'J':
        if ( (name[1]|0x20) == 'a' )
            n = 1;
        else if ( (name[2]|0x20) == 'n' )
            n = 6;
        else if ( (name[2]|0x20) == 'l' )
            n = 7;
        break;
    case 'f': // "feb"
    case 'F':
        if ( (name[1]|0x20) == 'e' )
            n = 2;
        break;
    case 'm': // "mar" "may"
    case 'M':
        if ( (name[2]|0x20) == 'r' )
            n = 3;
        else if ( (name[2]|0x20) == 'y' )
            n = 5;
        break;
    case 'a': // "apr" "aug"
    case 'A':
        if ( (name[1]|0x20) == 'p' )
            n = 4;
        else if ( (name[1]|0x20) == 'u' )
            n = 8;
        break;
    case 's': // "sep"
    case 'S':
        if ( (name[1]|0x20) == 'e' )
            n = 9;
        break;
    case 'o': // "oct"
    case 'O':
        if ( (name[2]|0x20) == 't' )
            n = 10;
        break;
    case 'n': // "nov"
    case 'N':
        if ( (name[1]|0x20) == 'o' )
            n = 11;
        break;
    case 'd': // "dec"
    case 'D':
        if ( (name[1]|0x20) == 'e' )
            n = 12;
        break;
    }
    return n;
}


// return true if this may possibly be a weekday.
static bool weekday( const String & name )
{
    if ( month( name ) )
        return false;

    uint n = 0;
    while ( ( name[n] >= 'A' && name[n] <= 'Z' ) ||
            ( name[n] >= 'a' && name[n] <= 'z' ) ||
            ( name[n] >= 128 ) )
        n++;
    if ( n < name.length() )
        return false;

    return true;
}


/*! Sets this date object to reflect the RFC 2822-format date \a s. If
    there are any syntax errors, the date is set to be invalid.

    A number of common syntax errors are accepted.
*/

void Date::setRfc822( const String & s )
{
    Parser822 p( s );
    String a;

    d->reset();

    // we'll understand 2822, but a bit kinder.

    // perhaps this is all bad. perhaps we should scan the string for
    // understandable tokens and try to build hh:mm:ss and so on
    // wherever they are. each token is then a string of letters and
    // digits, and we know what's between. each token can have
    // capabilities. for a number, its size defines its capabilities.

    // may do that later. not now. for now, we use the 2822+sucky hacks
    // approach.

    // skip over introductory day of week
    a = p.string();
    p.comment();
    if ( p.next() == '.' ) // sometimes people add an incorrect dot.
        (void)p.character();

    if ( p.next() == ',' ) {
        (void)p.character();
        a = p.string();
    }
    else {
        // sometimes there's no comma.
        if ( weekday( a ) )
            a = p.string();
    }

    // next comes the date. it _should_ be 13 dec 2003, but we'll also
    // accept 13 dec 03, dec 13 03 and dec 13 2003.

    String s1 = a;
    p.comment(); // and we'll accept 13, dec 2003
    if ( p.next() == ',' )
        (void)p.character();
    bool ok = false;
    String s2;
    bool yearAtEnd = false;
    // this whole block is for Date: 13-Dec-2003
    if ( s1[2] == '-' ) {
        d->day = s1.mid( 0, 2 ).number( &ok );
        if ( !ok )
            return;
        d->month = month( s1.mid( 3, 3 ) );
        if ( !d->month )
            return;
        a = s1.mid( 7 );
    }
    else {
        // and this bit for the legal way
        s2 = p.string();
        if ( s1[0] > '9' ) {
            a = s1;
            s1 = s2;
            s2 = a;
        }
        d->day = s1.number( &ok );
        if ( !ok )
            return;

        d->month = month( s2 );

        if ( d->month == 0 ) {
            // also accept numerical months. fucked, but...
            ok = false;
            d->month = s2.number( &ok );
            if ( d->month > 12 || !ok )
                d->month = 0;
        }
        else {
            // Some programs (which urgently need potty training) put a dot
            // after the month's name.
            if ( p.next() == '.' )
                p.step();
        }

        a = p.string();
        if ( a.length() < 3 && p.next() == ':' )
            yearAtEnd = true;
    }
    
    if ( d->month < 1 || d->month > 12 )
        return;

    if ( !yearAtEnd ) {
        // we process the year where it should be.
        ok = false;
        d->year = a.number( &ok );
        if ( !ok )
            return;

        if ( d->year < 20 )
            d->year += 2000;
        else if ( d->year < 100 )
            d->year += 1900;

        // ok. time is next. conveniently : is a tspecial.
        a = p.string();
    }

    d->hour = a.number( &ok );
    if ( !ok || d->hour > 23 )
        return;

    p.comment();
    if ( p.next() != ':' && p.next() != '.' ) // one legal, the other not.
        return;
    p.character();

    a = p.string();
    d->minute = a.number( &ok );
    if ( !ok || d->minute > 59 )
        return;

    p.comment();
    if ( p.next() == ':' || p.next() == '.' ) {
        p.character();

        a = p.string();
        d->second = a.number( &ok );
        if ( !ok || d->second > 60 )
            return;
    }

    // timezone: +0530. we're stricter than the rfc: we demand that
    // the minute part be 0 <= x <= 59 and the hour 0 <= x <= 29.


    String tzn = p.comment();
    d->tz = 0;
    bool tzok = false;
    a = p.string();
    if ( a.lower().startsWith( "gmt+" ) && p.next() == ':' ) {
        // lycos webmail has its own ideas about date fields. their
        // implementation is apparently not based on either RFC 822 or
        // 2822, but on an RFC written at the University of Mars.
        p.character();
        a = a.mid( 3 ) + p.string();
    }
    if ( a.length() == 5 &&
         ( a[0] == '+' || a[0] == '-' ) &&
         ( a[1] >= '0' && a[1] <= '2' ) &&
         ( a[2] >= '0' && a[2] <= '9' ) &&
         ( a[3] >= '0' && a[3] <= '5' ) &&
         ( a[4] >= '0' && a[4] <= '9' ) ) {
        bool dummy;
        d->tz = a.mid( 3 ).number( &dummy ) + 60 *
                a.mid( 1, 2 ).number( &dummy );
        if ( a[0] == '-' ) {
            d->tz = 0 - d->tz;
            if ( d->tz == 0 )
                d->minus0 = true; // what a hack.
        }
        tzok = true;
    }
    else if ( a[0] >= '0' && a[0] <= '9' && yearAtEnd ) {
        // having the year at the end doesn't necessarily mean at the
        // very end...
        ok = false;
        d->year = a.number( &ok );
        if ( ok ) {
            yearAtEnd = false;
            if ( d->year < 60 )
                d->year += 2000;
            else if ( d->year < 100 )
                d->year += 1900;
        }
    }
    else {
        // could it be that we're looking at the time zone NAME, not
        // in a comment?
        a = a.lower();
        uint j = 0;
        while ( zones[j].name != 0 && zones[j].name != a )
            j++;
        if ( zones[j].name != 0 )
            tzn = a;
    }

    // that's all. the date is valid.

    a = p.comment();
    if ( !a.isEmpty() )
        tzn = a;
    tzn = tzn.lower();

    if ( d->minus0 ) {
        // in this case we really don't want to hand out a zone
    }
    else if ( tzok && !tzn.isEmpty() ) {
        uint j = 0;
        while ( zones[j].name != 0 && zones[j].name != tzn )
            j++;
        if ( zones[j].name == tzn && zones[j].offset == d->tz )
            d->tzn = zones[j].name;
    }
    else if ( !tzn.isEmpty() ) {
        uint j = 0;
        while ( zones[j].name != 0 && zones[j].name != tzn )
            j++;
        if ( zones[j].name == tzn ) {
            d->tzn = zones[j].name;
            d->tz = zones[j].offset;
            tzok = true;
        }
    }
    else if ( !tzok ) {
        // no time zone supplied, also no comment name. we fall back
        // to -0000. hardly ideal.
        d->minus0 = true;
    }

    if ( yearAtEnd ) {
        // what a crock.
        a = p.string();
        ok = false;
        d->year = a.number( &ok );
        if ( !ok )
            return;

        if ( d->year < 60 )
            d->year += 2000;
        else if ( d->year < 100 )
            d->year += 1900;
    }

    d->valid = true;
    checkHarder();
    if ( !d->valid )
        return;

    if ( d->tz < 14*60 && d->tz >-14*60 )
        return; // fine.

    // some spammers use time zones like +1900, and about 5,000 people
    // in the eastern part of Kiribati use timezone +1400. since
    // postgres cannot store that, we convert the date to GMT, or
    // rather to -0000.
    setUnixTime( unixTime() );
    d->minus0 = true;
}



/* day-of-week from year/month/day, using the CACM algorithm also used
   in Qt. Communications of the ACM, Vol 6, No 8. */

static int dow( int y, int m, int d )
{
    if ( m > 2 ) {
        m -= 3;
    } else {
        m += 9;
        y--;
    }
    int c = y/100;
    int ya = y - 100*c;
    return (1721119 + d + (146097*c)/4 + (1461*ya)/4 + (153*m+2)/5)%7;
}


// these two may be candidates for String...
static String zeroPrefixed( int n, uint w )
{
    String z( "0000" );
    z.append( fn( n ) );
    return z.mid( z.length()-w );
}


static int abs( int i )
{
    if ( i > 0 )
        return i;
    return -i;
}

/*! Returns the date in RFC 822 format. If it's too far into the past
  or future, the weekday is omitted (as is legal).

  Returns an empty string if the date is invalid.
*/

String Date::rfc822() const
{
    String r;
    if ( !valid() )
        return r;

    if ( d->year > 1925 && d->year < 2100 ) {
        int wd = dow( d->year, d->month, d->day );
        r.append( weekdays[wd] );
        r.append( ", " );
    }

    r.append( fn( d->day ) );
    r.append( " " );
    r.append( months[d->month-1] );
    r.append( " " );
    r.append( fn( d->year ) );
    r.append( " " );
    r.append( zeroPrefixed( d->hour, 2 ) );
    r.append( ":" );
    r.append( zeroPrefixed( d->minute, 2 ) );
    r.append( ":" );
    r.append( zeroPrefixed( d->second, 2 ) );
    r.append( " " );

    if ( d->minus0 || d->tz < 0 )
        r.append( "-" );
    else
        r.append( "+" );

    r.append( zeroPrefixed( abs( d->tz ) / 60, 2 ) );
    r.append( zeroPrefixed( abs( d->tz ) % 60, 2 ) );

    if ( !d->minus0 && d->tzn.length() > 0 ) {
        r.append( " (" );
        r.append( d->tzn.upper() );
        r.append( ")" );
    }

    return r;
}


/*! Returns an IMAP-format date-time, or an empty string if the date
  is invalid.

  (date-day-fixed "-" date-month "-" date-year SP time SP zone)

*/

String Date::imap() const
{
    String r;
    if ( !d->valid )
        return r;

    r.append( zeroPrefixed( d->day, 2 ) );
    r.append( "-" );
    r.append( months[ d->month-1 ] );
    r.append( "-" );
    r.append( zeroPrefixed( d->year, 4 ) );
    r.append( " " );
    r.append( zeroPrefixed( d->hour, 2 ) );
    r.append( ":" );
    r.append( zeroPrefixed( d->minute, 2 ) );
    r.append( ":" );
    r.append( zeroPrefixed( d->second, 2 ) );
    r.append( " " );

    if ( d->minus0 || d->tz < 0 )
        r.append( "-" );
    else
        r.append( "+" );

    r.append( zeroPrefixed( abs( d->tz ) / 60, 2 ) );
    r.append( zeroPrefixed( abs( d->tz ) % 60, 2 ) );

    return r;
}


/*! Sets the date to the supplied (in this order) \a year, \a month,
    \a day, \a hour, \a minute, \a second, \a zone, all of which are
    presumed to be sensible. If they aren't sensible, the object
    becomes invalid.
*/

void Date::setDate( uint year, uint month, uint day,
                    uint hour, uint minute, uint second,
                    int zone )
{
    d->reset();

    d->year = year;
    d->month = month;
    d->day = day;
    d->hour = hour;
    d->minute = minute;
    d->second = second;
    d->tz = zone;

    if ( d->month > 0 && d->year > 0 &&
         d->second <= 60 && d->minute <= 59 && d->hour <= 23 &&
         d->day <= 31 && d->hour >= 0 )
        d->valid = true;
    checkHarder();
}


/*! \overload
    A version of setDate() that takes a \a month name instead of a
    number, for use with IMAP (as opposed to ISO) date-time. The
    \a year, \a day, \a hour, \a minute, \a second, and \a zone
    arguments are handled identically.
*/

void Date::setDate( uint year, const String & month, uint day,
                    uint hour, uint minute, uint second,
                    int zone )
{
    setDate( year, ::month( month ), day, hour, minute, second, zone );
}


/*! Returns true if the object is a legal date, and false if the date
    is meaningless, unparsable or uninitialized. */

bool Date::valid() const
{
    return d->valid;
}


/*! Returns the date part of the object as a ten-character ISO8601
    date, eg. "2004-02-29".
*/

String Date::isoDate() const
{
    String r;
    if ( d->valid )
        r = zeroPrefixed( d->year, 4 ) + "-" +
            zeroPrefixed( d->month, 2 ) + "-" +
            zeroPrefixed( d->day, 2 );
    return r;
}


/*! Returns the time part of the object as an eight-character ISO8601
    string, e.g. "01:22:59".

    Returns an empty string if the date is invalid.
*/

String Date::isoTime() const
{
    String r;
    if ( d->valid )
        r = zeroPrefixed( d->hour, 2 ) + ":" +
            zeroPrefixed( d->minute, 2 ) + ":" +
            zeroPrefixed( d->second, 2 );
    return r;
}


/*! Returns the timezone offset, or 0 if the date is invalid. Note
    that +0000 and -0000 are indistinguishable in the Date API.
*/

int Date::offset() const
{
    if ( !d->valid )
        return 0;
    return d->tz;
}


/*! Returns the ISO-format date (date, time, offset all mangled
    together).
*/

String Date::isoDateTime() const
{
    String r;
    if ( !d->valid )
        return r;

    r = isoDate();
    r.append( " " );
    r.append( isoTime() );
    int tz = d->tz;
    if ( d->tz < 0 ) {
        r.append( " -" );
        tz = -tz;
    }
    else {
        r.append( " +" );
    }
    r.append( fn( tz / 60 ) );
    r.append( ":" );
    r.append( zeroPrefixed( tz%60, 2 ) );
    return r;
}


/*! Checks that a presumably valid date really is. Flags November 31
    as invalid, all dates before 1900 ditto, etc, etc.
*/

void Date::checkHarder()
{
    if ( !d->valid )
        return;

    // simple code for the simple cases
    if ( d->year < 1600 )
        d->valid = false;
    else if ( d->day > 30 &&
              ( d->month ==  4 || // april
                d->month ==  6 || // june
                d->month ==  9 || // september
                d->month == 11 )) // november
        d->valid = false;
    else if ( d->month == 2 && d->day > 29 )
        d->valid = false;

    if ( d->month != 2 || d->day < 29 || !d->valid )
        return;

    // leap years, valid from 1900 to whenever
    if ( ( d->year % 400 ) == 0 ) {
        // ok, is a leap year
    }
    else if ( ( d->year % 100 ) == 0 ) {
        // is not a leap year
        d->valid = false;
    }
    else if ( ( d->year % 4 ) == 0 ) {
        // ok, is a leap year
    }
    else {
        d->valid = false;
    }
}
