#ifndef __COMMAND_H__
#define __COMMAND_H__

#include "list.h"
#include "global.h"
#include "set.h"


class String;
class IMAP;
class Arena;
class Logger;


class Command {
public:
    Command();
    virtual ~Command();

    static Command * create( IMAP *, const String &, const String &,
                             List<String> *, Arena * );

    virtual void parse();
    virtual void execute() = 0;
    virtual void read();
    bool ok() const;

    enum State { Blocked, Executing, Finished };

    State state() const;
    void setState( State );

    uint group() const;
    void setGroup( uint );

    Arena * arena() const;

    Logger * logger() const;

    enum Response { Tagged, Untagged };
    void respond( const String &, Response = Untagged );

    enum Error { No, Bad };
    void error( Error, const String & );

    void emitResponses();

    void end();
    void nil();
    void space();
    uint number();
    uint nzNumber();
    String nstring();
    String astring();
    String string();
    String atom();
    String quoted();
    String literal();
    Set set();
    char nextChar();
    void step();

    IMAP * imap() const;

private:
    const String following() const;

private:
    class CommandData * d;

    friend class CommandTest;
};

#endif
