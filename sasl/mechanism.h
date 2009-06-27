// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MECHANISM_H
#define MECHANISM_H

#include "log.h"
#include "event.h"
#include "estring.h"
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
    EString name() const;

    enum State {
        AwaitingInitialResponse,
        IssuingChallenge, AwaitingResponse, Authenticating,
        Succeeded, Failed, Terminated
    };
    State state() const;
    void setState( State );

    void execute();
    void readInitialResponse( const EString * );
    void readResponse( const EString * );
    virtual EString challenge();
    virtual void parseResponse( const EString & ) = 0;
    virtual void verify();

    bool done() const;

    User * user() const;
    UString login() const;
    void setLogin( const UString & );
    void setLogin( const EString & );
    UString secret() const;
    void setSecret( const UString & );
    void setSecret( const EString & );
    UString storedSecret() const;
    void setStoredSecret( const UString & );
    virtual void setChallenge( const EString & );

    static SaslMechanism * create( const EString &, EventHandler *,
                                   class SaslConnection * );

    static bool allowed( Type, bool );
    static EString allowedMechanisms( const EString &, bool );

    void log( const EString &, Log::Severity = Log::Info );

    void tick();

protected:
    SaslMechanism( EventHandler *, Type );
private:
    class SaslData *d;
};


#endif
