#include "expunge.h"

#include "../imap.h"

void Expunge::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
