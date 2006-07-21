// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DSN_H
#define DSN_H

#include "string.h"
#include "list.h"

class Message;


class Recipient
    : public Garbage
{
public:
    Recipient();

    void setOriginalRecipient( class Address * );
    class Address * originalRecipient() const;

    void setFinalRecipient( class Address * );
    class Address * finalRecipient() const;

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

    bool valid() const;

private:
    class RecipientData * d;
};


class DSN
    : public Garbage
{
public:
    DSN();

    void setMessage( Message * );
    Message * message() const;

    void setEnvelopeId( const String & );
    String envelopeId() const;

    void setFullReport( bool );
    bool fullReport() const;

    void setReceivedFrom( const String & );
    String receivedFrom() const;

    void setArrivalDate( class Date * );
    Date * arrivalDate() const;

    List<Recipient> * recipients() const;
    void addRecipient( Recipient * );

    Message * result() const;

    bool allOk() const;
    bool allFailed() const;

    String plainBody() const;
    String dsnBody() const;

    bool valid() const;

private:
    class DSNData * d;
};


#endif
