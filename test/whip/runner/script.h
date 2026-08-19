// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SCRIPT_H
#define SCRIPT_H

class File;


#include "estring.h"


class TestScript
    : public Garbage
{
public:
    TestScript( File * f );

    EString provides() const;
    EString depends() const;
    EString name() const;


    enum Action { Command, Connect, Listen, 
                  Send, Receive, Use, Close, Obliterate,
                  Done };
    Action action() const;
    EString protocol() const;
    uint port();
    EString clientName() const;
    EString string();

    void start();
    void step();

    static TestScript * findProvider( const EString & );

    bool failed() const;
    void setFailed( bool );

    bool necessary() const;
    void setNecessary( bool );
    
    bool broken() const;

private:
    void parse( File * );
    void parseLine( const EString & );
    void error( EString );

private:
    class TestScriptData * d;
};


#endif
