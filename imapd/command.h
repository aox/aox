#ifndef COMMAND_H
#define COMMAND_H

#include "global.h"
#include "string.h"
#include "list.h"


class IMAP;
class Arena;
class Log;
class Set;


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

    enum State { Blocked, Executing, Waiting, Finished };

    State state() const;
    void setState( State );

    uint group() const;
    void setGroup( uint );

    void wait( int );
    
    Arena * arena() const;

    Log * logger() const;

    enum Response { Tagged, Untagged };
    void respond( const String &, Response = Untagged );

    enum Error { No, Bad };
    void error( Error, const String & );

    void emitResponses();

    String digits( uint, uint );
    String letters( uint, uint );
    void end();
    void nil();
    void space();
    uint number();
    uint nzNumber();
    uint msn();
    String nstring();
    String astring();
    String string();
    String atom();
    String quoted();
    String literal();
    Set set( bool );
    String flag();
    char nextChar();
    void step( uint = 1 );
    const String following() const;
    void require( const String & );
    bool present( const String & );

    IMAP * imap() const;

private:
    class CommandData * d;

    friend class CommandTest;
};

#endif
