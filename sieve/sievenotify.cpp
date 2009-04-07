// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sievenotify.h"

#include "sieveproduction.h"
#include "addressfield.h"
#include "estringlist.h"
#include "address.h"
#include "header.h"
#include "field.h"


class SieveNotifyMethodData
    : public Garbage
{
public:
    SieveNotifyMethodData()
        : Garbage(),
          command( 0 ),
          type( SieveNotifyMethod::Invalid ),
          header( 0 )
        {}

    SieveProduction * command;

    SieveNotifyMethod::Type type;

    UString message;

    // if the type is Mailto
    Header * header;

};



/*! Constructs a SieveNotifyMethod object to parse and generally check
    \a url.

    Reports errors using\a argument if that is non-null, otherwise
    using \a command.
*/

SieveNotifyMethod::SieveNotifyMethod( const UString & url,
                                      class SieveProduction * argument,
                                      class SieveProduction * command )
    : Garbage(), d( new SieveNotifyMethodData )
{
    d->command = command;
    if ( url.startsWith( "mailto:" ) ) {
        EString r = url.utf8().mid( 7 );
        AddressParser ap( r.section( "?", 1 ).deURI() );
        ap.assertSingleAddress();
        if ( !ap.error().isEmpty() ) {
            reportError( ap.error(), argument );
            return;
        }
        d->type = Mailto;
        d->header = new Header( Header::Rfc2822 );
        d->header->add( new AddressField( HeaderField::To,
                                          ap.addresses()->first() ) );
        if ( r.contains( '?' ) ) {
            r = r.mid( r.find( '?' ) + 1 );
            EStringList::Iterator i( EStringList::split( '&', r ) );
            while ( i ) {
                int x = i->find( '=' );
                EString n;
                if ( x >= 0 )
                    n = i->mid( 0, x ).deURI();
                EString v;
                if ( x >= 0 )
                    v = i->mid( x + 1 ).deURI();
                if ( n.isEmpty() ) {
                    reportError( "Empty URI field name in mailto link",
                                 argument );
                }
                else if ( v.isEmpty() ) {
                    reportError( "Empty URI field value in mailto link",
                                 argument );
                }
                else {
                    HeaderField * hf = HeaderField::create( n, v );
                    if ( hf->valid() )
                        d->header->add( hf );
                    else
                        reportError( "While parsing mailto:...?" + n +": " +
                                     hf->error(), argument );
                }
                ++i;
            }
        }

        if ( !d->header->addresses( HeaderField::From ) )
            d->header->add( "From", "invalid@invalid.invalid" ); // XXX

        if ( !d->header->valid() )
            reportError( "Header for mailto message will be bad: " +
                         d->header->error(), argument );
    }
    else {
        d->type = Invalid;
    }
}


/*! Reports the error \a e via \a p if supplied, otherwise via the
    command().

*/

void SieveNotifyMethod::reportError( const EString & e, SieveProduction * p )
{
    if ( p )
        p->setError( e );
    else
        d->command->setError( e );
}


/*! Returns the command argument to the constructor. */

SieveProduction * SieveNotifyMethod::command() const
{
    return d->command;
}


/*! Parses \a f as an email address and records that it should be used
    as From, and that any errors should be recorded via \a a.
*/

void SieveNotifyMethod::setFrom( const UString & f, SieveProduction * a )
{
    AddressParser p( f.utf8() );
    p.assertSingleAddress();
    if ( !p.error().isEmpty() )
        reportError( p.error(), a );
    setFrom( p.addresses()->first() );
}


/*! Records that \a f should be used as the From address. Applies only
    if type() is Mailto.
*/

void SieveNotifyMethod::setFrom( Address * f )
{
    d->header->removeField( HeaderField::From );
    d->header->add( new AddressField( HeaderField::From, f ) );
}


/*! Records that \a m should be sent as body text.

    This may cause errors. If it does, then they'll be reported via \a a.
*/

void SieveNotifyMethod::setMessage( const UString & m, SieveProduction * a )
{
    d->message = m;
    switch ( d->type ) {
    case Invalid:
        // we'll report its being invalid as an error elsewhere
        break;
    case Mailto:
        // mailto needs the default text or something else
        if ( d->message.isEmpty() )
            reportError( "Empty mail notifications make no sense", a );
        break;
    }
}


/*! Returns true if this object is valid, and false if there's
    something bad. Also reports the error using command().
*/

bool SieveNotifyMethod::valid()
{
    if ( d->header->valid() )
        return true;
    reportError( "Mailto header would be bad: " + d->header->error() );
    return false;
}


/*! Returns... hm, returns Unknown. We don't support any IM methods
    yet.

    I think that when we do add support for XMPP, this may still
    return Unknown for XMPP, if we've started looking but not found
    the answer yet.
*/

SieveNotifyMethod::Reachability SieveNotifyMethod::reachability() const
{
    return Unknown;
}
