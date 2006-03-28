// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MECHANISM_H
#define MECHANISM_H

#include "log.h"
#include "event.h"
#include "string.h"

class User;


class SaslMechanism
    : public EventHandler
{
public:
    SaslMechanism( EventHandler * );
    virtual ~SaslMechanism() {}

    enum State {
        AwaitingInitialResponse,
        IssuingChallenge, AwaitingResponse, Authenticating,
        Succeeded, Failed, Terminated
    };
    State state() const;
    void setState( State );

    void execute();
    virtual String challenge();
    virtual void readResponse( const String & ) = 0;
    virtual void verify();

    bool done() const;

    User * user() const;
    String login() const;
    void setLogin( const String & );
    String secret() const;
    void setSecret( const String & );
    String storedSecret() const;
    void setStoredSecret( const String & );
    virtual void setChallenge( const String & );

    static SaslMechanism * create( const String &, EventHandler * );

    void log( const String &, Log::Severity = Log::Info );

private:
    class SaslData *d;
};


#endif
