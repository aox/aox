#include "namespace.h"

#include "imap.h"

/*! \class Namespace namespace.h
    Implements the NAMESPACE extension specified in RFC 2342.
*/


/*! \reimp */

void Namespace::execute()
{
    String personal, other, shared;

    personal = "((\"\" \"/\") (\"/users/"+ imap()->login() +"/\" \"/\"))";
    other    = "((\"/users/\"  \"/\"))";
    shared   = "((\"/\" \"/\"))";

    respond( "NAMESPACE " + personal + " " + other + " " + shared );
    finish();
}
