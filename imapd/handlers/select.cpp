#include "select.h"

#include "../imap.h"

void Select::parse()
{
    m = astring();
    end();
}

void Select::execute()
{
    if ( m == "inbox" ) {
        imap()->setState( IMAP::Selected );
    }
    else {
        imap()->setState( IMAP::Authenticated );
        error( No, "Can't SELECT mailbox " + m );
    }
    setState( Finished );
}
