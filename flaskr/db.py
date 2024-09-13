import sqlite3
import click
from flask import current_app, g

#function that creates a connection with the database
def get_db():
    #check if database was created
    if 'db' not in g:
        #g is being used to store the database connection
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

#it starts the database
def init_db():
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))
#restart the database    
@click.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')

def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()

#register commands
#quando registrado no __init__.py conseguimos rodar o comando pelo cmd
def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)