// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FETCH_H
#define FETCH_H

#include "command.h"


class Message;
class Bodypart;
class Multipart;


class Fetch
    : public Command
{
public:
    Fetch( bool = false );

    void parse();
    void execute();

private:
    void parseAttribute( bool );
    void parseBody();
    void removeInvalidUids();
    void sendFetchQueries();
    String dotLetters( uint, uint );
    String flagList( Message *, uint );
    String internalDate( Message * );
    String envelope( Message * );
    String bodyStructure( Multipart *, bool );
    String singlePartStructure( Bodypart *, bool );
    String fetchResponse( Message *, uint, uint );

private:
    class FetchData * d;
};


#endif
