// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RETENTION_H
#define RETENTION_H

#include "aoxcommand.h"


class SetRetention
    : public AoxCommand
{
public:
    SetRetention( EStringList * );

    void execute();

private:
    class SetRetentionData * d;
};


class ShowRetention
    : public AoxCommand
{
public:
    ShowRetention( EStringList * );

    void execute();

private:
    class ShowRetentionData * d;
};


#endif
