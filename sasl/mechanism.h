#ifndef MECHANISM_H
#define MECHANISM_H

#include "string.h"
#include "log.h"

class EventHandler;


class SaslMechanism {
public:
    SaslMechanism( EventHandler * );
    virtual ~SaslMechanism() {}

    enum State {
        AwaitingInitialResponse,
        IssuingChallenge, AwaitingResponse, Authenticating,
        Succeeded, Failed
    };
    State state() const;
    void setState( State );

    EventHandler *command() const;
    void log( Log::Severity, const String & );
    void log( const String & );

    void query();
    virtual String challenge();
    virtual void readResponse( const String & ) = 0;
    virtual void verify();

    bool done() const;
    uint uid() const;

    String login() const;
    void setLogin( const String & );
    String secret() const;
    void setSecret( const String & );
    String storedSecret() const;
    void setStoredSecret( const String & );
    virtual void setChallenge( const String & );

    static SaslMechanism * create( const String &, EventHandler * );

private:
    class SaslData *d;
};


#endif
