// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SERVERS_H
#define SERVERS_H

#include "aoxcommand.h"
#include "list.h"


class Checker
    : public EventHandler
{
public:
    Checker( int, EventHandler * );

    void execute();
    bool done() const;
    bool failed() const;

private:
    class CheckerData * d;
};


class Starter
    : public EventHandler
{
public:
    Starter( int, EventHandler * );

    void execute();
    bool done() const;
    bool failed() const;

private:
    class StarterData * d;
    bool startServer( const char * );
};


class Stopper
    : public EventHandler
{
public:
    Stopper( int, EventHandler * );

    void execute();
    bool done() const;
    bool failed() const;

    void connect();
    void disconnect();

private:
    class StopperData * d;
};


class CheckConfig
    : public AoxCommand
{
public:
    CheckConfig( EStringList * );
    void execute();

private:
    class Checker * checker;
};


class Start
    : public AoxCommand
{
public:
    Start( EStringList * );
    void execute();

private:
    class StartData * d;
};


class Stop
    : public AoxCommand
{
public:
    Stop( EStringList * );
    void execute();

private:
    class Stopper * stopper;
};


class Restart
    : public AoxCommand
{
public:
    Restart( EStringList * );
    void execute();

private:
    class RestartData * d;
};


class ShowStatus
    : public AoxCommand
{
public:
    ShowStatus( EStringList * );
    void execute();
};


class ShowBuild
    : public AoxCommand
{
public:
    ShowBuild( EStringList * );
    void execute();
};


class ShowConfiguration
    : public AoxCommand
{
public:
    ShowConfiguration( EStringList * );
    void execute();

private:
    void addVariable( SortedList<EString> *,
                      EString, EString, EString, bool );
};


#endif
