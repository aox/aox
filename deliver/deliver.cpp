#include "log.h"
#include "string.h"
#include "address.h"
#include "parser.h"
#include "buffer.h"
#include "message.h"
#include "configuration.h"
#include "date.h"
#include "header.h"
#include "injector.h"
#include "mailbox.h"
#include "arena.h"
#include "scope.h"
#include "test.h"
#include "log.h"
#include "logclient.h"
#include "occlient.h"
#include "database.h"
#include "file.h"
#include "loop.h"

#include <time.h> // XXX this needs to go. fix setTimeout().
#include <stdlib.h>


class DeliveryDbClient: public EventHandler
{
public:
    DeliveryDbClient();
    void execute();

    Injector * injector;
};


DeliveryDbClient::DeliveryDbClient()
    : EventHandler(), injector( 0 )
{
}


void DeliveryDbClient::execute()
{
    if ( injector && injector->done() )
        Loop::shutdown();
}


int main( int argc, char ** argv )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    OCClient::setup();
    Database::setup();
    Mailbox::setup();

    log( "delivery agent started" );
    log( Test::report() );

    Configuration::global()->report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    File input( "/proc/fd/self/stdin", File::Read ); // ### evil hack
    String contents = input.contents(); // ### use Buffer instead
    Message * m = new Message( contents, true ); // <- be strict? really?
    Mailbox * inbox = Mailbox::find( argv[1] );
    if ( !inbox ) {
        exit( -1 );
    }
    List<Mailbox> * inboxes = new List<Mailbox>;
    inboxes->append( inbox );
    
    DeliveryDbClient * helper = new DeliveryDbClient;
    Injector * i = new Injector( m, inboxes, helper );
    helper->injector = i;

    Loop::start();
}
