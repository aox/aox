#include "append.h"

#include "date.h"
#include "string.h"
#include "list.h"


/*! \class Append append.h
  \brief The Append class implements the IMAP APPEND command.

  APPEND is one of several ways to inject mail into the mailstore. In
  theory. In practice it's the only one so far, or arguably there is
  no way. Some of the code in here will need to be split off and put
  into an class shared by the SMTP/LMTP server, APPEND and who knows
  what else.

  The MULTIAPPEND extension is probably not supportable. Append on its
  own has a memory use characteristic rather different from other
  commands, MULTIAPPEND would worsen that.
*/


class AppendData
{
public:
    Date date;
    String message;
    List< String > flags;
};


Append::Append()
    : Command(), d( new AppendData )
{
    // nothing more needed
}


void Append::parse()
{

    // the grammar used is:
    // append = "APPEND" SP mailbox SP [flag-list SP] [date-time SP] literal
    String mailbox = astring();
    space();

    if ( present( "(" ) ) {
        step();
        d->flags.append( new String( flag() ) );
        while( nextChar() == ' ' ) {
            space();
            d->flags.append( new String( flag() ) );
        }
        require( ")" );
        space();
    }

    if ( present( "\"" ) ) {
        uint day;
        if ( nextChar() == ' ' ) {
            space();
            day = number( 1 );
        }
        else {
            day = number( 2 );
        }
        require( "-" );
        String month = letters( 3, 3 );
        require( "-" );
        uint year = number( 4 );
        space();
        uint hour = number( 2 );
        require( ":" );
        uint minute = number( 2 );
        require( ":" );
        uint second = number( 2 );
        space();
        int zone = 1;
        if ( nextChar() == '-' )
            zone = -1;
        else if ( nextChar() != '+' )
            error( Bad, "Time zone must start with + or -" );
        step();
        zone = zone * ( ( 60 * number( 2 ) ) + number( 2 ) );
        require( "\"" );
        space();
        d->date.setDate( year, month, day, hour, minute, second, zone );
        if ( !d->date.valid() )
            error( Bad, "Date supplied is not valid" );
    }

    d->message = literal();
}


/*! This new number() demands \a n digits and returns the number.
*/

uint Append::number( uint n )
{
    String tmp = digits( n, n );
    return tmp.number( 0 );
}


void Append::execute()
{
    respond( "Ignoring unimplemented command", Untagged );
    setState( Finished );
}
