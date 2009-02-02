// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RECIPIENT_H
#define RECIPIENT_H

#include "estring.h"


class Address;
class Mailbox;


class Recipient
    : public Garbage
{
public:
    Recipient();
    Recipient( Mailbox * );
    Recipient( Address *, Mailbox * );

    void setOriginalRecipient( Address * );
    Address * originalRecipient() const;

    void setFinalRecipient( Address * );
    Address * finalRecipient() const;

    enum Action { Unknown, Failed, Delayed, Delivered, Relayed, Expanded };

    void setAction( Action, const EString & );
    Action action() const;
    EString status() const;

    void setRemoteMTA( const EString & );
    EString remoteMTA() const;

    void setDiagnosticCode( const EString & );
    EString diagnosticCode() const;

    void setLastAttempt( class Date * );
    Date * lastAttempt() const;

    void setFinalLogId( const EString & );
    EString finalLogId() const;

    EString plainTextParagraph() const;
    EString dsnParagraph() const;

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    bool valid() const;

    bool operator <=( const Recipient & );

private:
    class RecipientData * d;
};


#endif
