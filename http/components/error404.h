// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ERROR404_H
#define ERROR404_H

#include "pagecomponent.h"

class Link;


class Error404
    : public PageComponent
{
public:
    Error404( Link * );
};


#endif
