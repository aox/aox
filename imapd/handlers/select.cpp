#include "select.h"

#include "../imap.h"

void Select::parse()
{
    m = astring();
    end();
}

void Select::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
