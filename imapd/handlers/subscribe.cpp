#include "subscribe.h"

#include "../imap.h"

void Subscribe::parse()
{
    m = astring();
    end();
}

void Subscribe::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
