// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVEACTION_H
#define SIEVEACTION_H

#include "global.h"

class String;
class UString;
class Mailbox;
class Address;
class Message;
class EventHandler;


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

    void setMessage( Message * );
    Message * message() const;

    void setErrorMessage( const String & );
    String errorMessage() const;

    bool done() const;
    bool failed() const;

private:
    class SieveActionData * d;
};


#endif
