#include "namespace.h"

#include "imap.h"

/*! \class Namespace namespace.h
    Implements the NAMESPACE extension specified in RFC 2342.

    Mailstore uses a single namespace, and this command informs the
    client about how this space is set up. Notably,
    /users/<name>/... is the same as ..., and other users are in
    /users/.
*/


void Namespace::execute()
{
    String personal, other, shared;

    personal = "((\"\" \"/\") (\"/users/"+ imap()->login() +"/\" \"/\"))";
    other    = "((\"/users/\" \"/\"))";
    shared   = "((\"/\" \"/\"))";

    respond( "NAMESPACE " + personal + " " + other + " " + shared );
    finish();
}
