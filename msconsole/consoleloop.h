// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CONSOLELOOP_H
#define CONSOLELOOP_H

#include "eventloop.h"
#include <qsocketnotifier.h>


class ConsoleLoop
    : public EventLoop
{
public:
    ConsoleLoop();

    void stop();
    void shutdown();
    void addConnection( Connection * c );
    void removeConnection( Connection * );

private:
    class ConsoleLoopData * d;
};


class WriteNotifier
    : public QSocketNotifier
{
    Q_OBJECT

public:
    WriteNotifier( int, Connection * );

public slots:
    void dispatch();

private:
    Connection * c;
};


class ReadNotifier
    : public QSocketNotifier
{
    Q_OBJECT

public:
    ReadNotifier( int, Connection * );
    Connection *connection() const;

public slots:
    void dispatch();

private:
    Connection * c;
};


#endif
