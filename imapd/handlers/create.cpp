#include "create.h"

#include "imap.h"

void Create::parse()
{
    m = astring();
    end();
}

void Create::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
