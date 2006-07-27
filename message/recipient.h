// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RECIPIENT_H
#define RECIPIENT_H

#include "string.h"


class Address;
class Mailbox;


class Recipient
    : public Garbage
{
public:
    Recipient();
    Recipient( Mailbox * );

    void setOriginalRecipient( Address * );
    Address * originalRecipient() const;

    void setFinalRecipient( Address * );
    Address * finalRecipient() const;

    enum Action { Unknown, Failed, Delayed, Delivered, Relayed, Expanded };

    void setAction( Action, const String & );
    Action action() const;
    String status() const;

    void setRemoteMTA( const String & );
    String remoteMTA() const;

    void setDiagnosticCode( const String & );
    String diagnosticCode() const;

    void setLastAttempt( class Date * );
    Date * lastAttempt() const;

    void setFinalLogId( const String & );
    String finalLogId() const;

    String plainTextParagraph() const;
    String dsnParagraph() const;

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    bool valid() const;

    bool operator <=( const Recipient & );

private:
    class RecipientData * d;
};


#endif
