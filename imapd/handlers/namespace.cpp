// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "namespace.h"

#include "imap.h"
#include "user.h"
#include "mailbox.h"

/*! \class Namespace namespace.h
    Implements the NAMESPACE extension specified in RFC 2342.

    Archiveopteryx uses a single namespace, and this command informs
    the client about how this space is set up.

    Because of client confusion, we no longer tell anyone about
    /users/<name>. It is the same as "", but we don't tell the client
    that explicitly.
*/


void Namespace::execute()
{
    String personal, other, shared;

    personal = "((\"\" \"/\"))";
    other    = "((\"/users/\" \"/\"))"; // XXX: hardcoded still
    shared   = "((\"/\" \"/\"))";

    respond( "NAMESPACE " + personal + " " + other + " " + shared );
    finish();
}
