// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef COMMAND_H
#define COMMAND_H

#include "imapresponse.h"
#include "permissions.h"
#include "estringlist.h"
#include "event.h"
#include "imap.h"

class Log;
class ImapParser;
class IntegerSet;


class Command
    : public EventHandler
{
public:
    Command();
    Command( IMAP * );
    virtual ~Command();

    static Command * create( IMAP *, const EString &, const EString &,
                             ImapParser * );

    virtual void parse();
    virtual void read();
    bool ok() const;

    void setParser( ImapParser * );
    ImapParser * parser() const;

    enum State { Unparsed, Blocked, Executing, Finished, Retired };
    State state() const;
    void setState( State );

    void setAllowedState( IMAP::State ) const;

    EString tag() const;
    EString name() const;

    bool usesMsn() const;

    uint group() const;
    void setGroup( uint );

    IMAP * imap() const;

    void respond( const EString & );
    void setRespTextCode( const EString & );

    enum Error { No, Bad };
    void error( Error, const EString & );

    void waitFor( ImapResponse * );
    void finish();
    virtual void emitResponses();
    void checkUntaggedResponses();

    char nextChar();
    void step( uint = 1 );
    bool present( const EString & );
    void require( const EString & );
    EString digits( uint, uint );
    EString letters( uint, uint );

    void nil();
    void space();
    uint number();
    uint nzNumber();
    uint objectId( char );
    EString atom();
    EString listChars();
    EString quoted();
    EString literal();
    EString string();
    EString nstring();
    EString astring();
    UString listMailbox();
    IntegerSet set( bool );
    uint msn();
    EString flag();
    class Mailbox * mailbox();
    UString mailboxName();

    void end();
    const EString following() const;

    enum QuoteMode {
        AString, NString, PlainString
    };
    static EString imapQuoted( const EString &,
                               const QuoteMode = PlainString );
    EString imapQuoted( Mailbox *, Mailbox * = 0 );

    void shrink( IntegerSet * );

    void requireRight( Mailbox *, Permissions::Right );
    bool permitted();

    ImapSession * session();

    MailboxGroup * mailboxGroup();

    class Transaction * transaction() const;
    void setTransaction( class Transaction * );

private:
    class CommandData *d;

    friend class CommandTest;
};


#endif
