// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVEACTION_H
#define SIEVEACTION_H

#include "global.h"

class String;
class Mailbox;
class Address;
class Message;
class EventHandler;


class SieveAction
    : public Garbage
{
public:
    enum Type { Reject, FileInto, Redirect, Discard, Error };

    SieveAction( Type );

    Type type() const;

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    void setAddress( Address * );
    Address * address() const;

    void setErrorMessage( const String & );
    String errorMessage() const;

    bool done() const;
    bool failed() const;

private:
    class SieveActionData * d;
};


#endif
