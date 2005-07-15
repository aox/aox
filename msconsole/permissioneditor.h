// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PERMISSIONEDITOR_H
#define PERMISSIONEDITOR_H

#include <qwidget.h>

#include "permissions.h"


class Mailbox;


class PermissionEditor
    : public QWidget
{
    Q_OBJECT
public:
    PermissionEditor( QWidget * parent );
    ~PermissionEditor();

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    void setupLayout();

    void add( const String &, const String & );

private slots:
    void addColumn();

private:
    class PermissionEditorData * d;
};


class PermissionEditorRow
    : public QObject
{
    Q_OBJECT
public:
    PermissionEditorRow( PermissionEditor * parent );
    ~PermissionEditorRow();

    class QCheckBox * button( Permissions::Right ) const;
    class QLabel * label() const;

private:
    class PermissionEditorRowData * d;
};


class PermissionEditorFetcher
    : public EventHandler
{
public:
    PermissionEditorFetcher( PermissionEditor *, Mailbox * );
    virtual ~PermissionEditorFetcher();

    void execute();

private:
    class PermissionEditorFetcherData * d;
};

#endif
