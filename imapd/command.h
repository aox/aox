#ifndef COMMAND_H
#define COMMAND_H

#include <list.h>
#include <global.h>

class String;
class IMAP;


class CommandData;

class Command
{
public:
    Command();
    virtual ~Command();

    static Command * create( IMAP *, const String &, const String &,
                             List<String> * );

    virtual void parse();
    virtual void execute() = 0;
    bool ok() const;

    enum Response { Tagged, Untagged };
    void respond( const String &, Response = Untagged );

    enum Error { No, Bad };
    void error( Error, const String & );

    void emitResponses();

    void end();
    void space();
    uint number();
    uint nzNumber();
    String astring();
    String atom();
    String quoted();
    String literal();
    char nextChar();
    void step();

    IMAP * imap() const;

private:
    const String following() const;

private:
    CommandData * d;
};

#endif
