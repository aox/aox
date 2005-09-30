// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sort.h"


class SortData
    : public Garbage
{
public:
    SortData()
    {}
};


/*! \class Sort sort.h
    Implements the SORT extension described in draft-ietf-imapext-sort.
*/


/*! Creates a new handler for SORT (or UID SORT, if \a u is true). */

Sort::Sort( bool u )
    : Search( u ),
      d( new SortData )
{
}


void Sort::parse()
{
    space();
    require( "(" );

    bool atEnd = false;
    while ( !atEnd ) {
        bool reverse = false;
        String item = letters( 1, 7 ).lower();

        if ( item == "reverse" ) {
            space();
            item = letters( 1, 7 ).lower();
            reverse = true;
        }

        if ( item == "arrival" )
            ;
        else if ( item == "cc" )
            ;
        else if ( item == "date" )
            ;
        else if ( item == "from" )
            ;
        else if ( item == "size" )
            ;
        else if ( item == "subject" )
            ;
        else if ( item == "to" )
            ;
        else
            error( Bad, "Unknown SORT key: " + item );

        if ( nextChar() == ' ' )
            space();
        else
            atEnd = true;
    }

    require( ")" );
    space();
    setCharset( astring() );

    space();
    parseKey();
    while ( nextChar() == ' ' ) {
        space();
        parseKey();
    }
    end();

    prepare();
}


void Sort::execute()
{
    finish();
}


void Sort::process()
{
}
