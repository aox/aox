// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MECHANISM_H
#define MECHANISM_H

#include "log.h"
#include "event.h"
#include "string.h"
#include "ustring.h"

class User;


class SaslMechanism
    : public EventHandler
{
public:
    virtual ~SaslMechanism() {}

    enum Type {
        Anonymous,
        Plain,
        Login,
        CramMD5,
        DigestMD5
    };
    Type type() const;
    String name() const;

    enum State {
        AwaitingInitialResponse,
        IssuingChallenge, AwaitingResponse, Authenticating,
        Succeeded, Failed, Terminated
    };
    State state() const;
    void setState( State );

    void execute();
    void readInitialResponse( const String * );
    void readResponse( const String * );
    virtual String challenge();
    virtual void parseResponse( const String & ) = 0;
    virtual void verify();

    bool done() const;

    User * user() const;
    UString login() const;
    void setLogin( const UString & );
    void setLogin( const String & );
    UString secret() const;
    void setSecret( const UString & );
    void setSecret( const String & );
    UString storedSecret() const;
    void setStoredSecret( const UString & );
    virtual void setChallenge( const String & );
    UString ldapdn() const;

    static SaslMechanism * create( const String &, EventHandler *,
                                   class SaslConnection * );

    static bool allowed( Type, bool );
    static String allowedMechanisms( const String &, bool );

    void log( const String &, Log::Severity = Log::Info );

    void tick();

protected:
    SaslMechanism( EventHandler *, Type );
private:
    class SaslData *d;
};


#endif
