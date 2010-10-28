// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SIEVEACTION_H
#define SIEVEACTION_H

#include "global.h"
#include "ustringlist.h"

class EString;
class UString;
class Mailbox;
class Address;
class EventHandler;
class Injectee;


class SieveAction
    : public Garbage
{
public:
    enum Type { Reject, FileInto, Redirect, Discard, Vacation, Error };

    SieveAction( Type );

    Type type() const;

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    void setSenderAddress( Address * );
    Address * senderAddress() const;

    void setRecipientAddress( Address * );
    Address * recipientAddress() const;

    void setHandle( const UString & );
    UString handle() const;

    void setExpiry( uint );
    uint expiry() const;

    void setMessage( Injectee * );
    Injectee * message() const;

    void setErrorMessage( const EString & );
    EString errorMessage() const;

    void setFlags( const UStringList & );
    UStringList flags() const;

    bool done() const;
    bool failed() const;

private:
    class SieveActionData * d;
};


#endif
