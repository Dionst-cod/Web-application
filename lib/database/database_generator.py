import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


class WP2DatabaseGenerator:
    def __init__(self, database_file, overwrite=False, initial_data=False):
        self.database_file = Path(database_file)
        self.create_initial_data = initial_data
        self.database_overwrite = overwrite
        self.test_file_location()
        self.conn = sqlite3.connect(self.database_file)

    def generate_database(self):
        self.create_table_users()
        self.create_table_agendas()
        self.create_table_events()
        agenda_id = self.create_demo_data()
        self.list_demo_events(agenda_id)

    def create_table_users(self):
        create_statement = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            date_created DATE NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
        self.__execute_transaction_statement(create_statement)
        print("✅ Table users created")

    def create_table_agendas(self):
        create_statement = """
        CREATE TABLE IF NOT EXISTS agendas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_name TEXT NOT NULL,
            title TEXT NOT NULL,
            external_stylesheet TEXT,
            date_created DATE NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
        self.__execute_transaction_statement(create_statement)
        print("✅ Table agendas created")

    def create_table_events(self):
        create_statement = """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            event_date DATE NOT NULL,
            start_time TEXT NOT NULL,            
            end_time TEXT NOT NULL,
            location TEXT NOT NULL,
            agenda_id INTEGER NOT NULL,
            date_created DATE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (agenda_id) REFERENCES agendas (id)
        );
        """
        self.__execute_transaction_statement(create_statement)
        print("✅ Table events created")

    def create_demo_data(self):
        if self.create_initial_data:
            admin_id = self.create_demo_users_and_return_last()
            agenda_id = self.create_demo_agendas_and_return_last()
            self.create_demo_events(agenda_id)
        return agenda_id

    def create_demo_agendas_and_return_last(self):
        create_statement = """
        INSERT INTO agendas (title, url_name)
        VALUES (?, ?);
        """
        list_of_parameters = [
            ("FRANKS Partyagenda", "partyagenda"),
            ("Collegerooster", "collegerooster"),
            ("Dartavonden 2021", "dartavonden"),
        ]
        for parameters in list_of_parameters:
            id = self.__execute_transaction_statement(create_statement, parameters)
        print("✅ Demo data agendas created")
        return id

    def create_demo_users_and_return_last(self):
        create_statement = """
        INSERT INTO users (username, password, is_admin)
        VALUES (?, ?, ?);
        """
        list_of_parameters = [
            ("user", "user", 0),
            ("user2", "user2", 0),
            ("admin", "admin", 1),
        ]
        for parameters in list_of_parameters:
            id = self.__execute_transaction_statement(create_statement, parameters)
        print("✅ Demo data users created")
        return id

    def create_demo_events(self, agenda_id):
        create_statement = """
            INSERT INTO events (name, description, event_date, start_time, end_time, location, agenda_id)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """
        today = datetime.now().date()
        thirty_days_future = today + timedelta(days=30)
        fourty_days_future = today + timedelta(days=40)
        list_of_parameters = [
            (
                "Open avond",
                "Vrij darten, de hele avond, iedereen is welkom",
                thirty_days_future,
                "19:00",
                "23:00",
                "Dartcafe de Schorre",
                agenda_id,
            ),
            (
                "10 euro tournooi",
                "Koppels tournooi, voor gevorde darters. Hoofdprijs is een nieuwe telefoon, een krat bier en een taxi naar huis!",
                fourty_days_future,
                "19:00",
                "23:00",
                "Dartcafe de Schorre",
                agenda_id,
            ),
        ]
        self.__execute_many_transaction_statement(create_statement, list_of_parameters)
        print("✅ Demo data events created")

    def list_demo_events(self, agenda_id):
        query = """
            SELECT * FROM agendas WHERE id = ?; 
        """
        agenda_results = self.__execute_query(query, parameters=(agenda_id,))
        agenda_url = agenda_results[0]["url_name"]

        query = """
        SELECT * FROM events WHERE event_date > ? and agenda_id = ?; 
        """
        # We maken hier een datum object aan met de huidige datum.
        today = datetime.now().date()

        # SQLite kan prima overweg met datetime objecten
        events = self.__execute_query(query, parameters=(today, agenda_id))
        print(f"Upcoming demo events in /agenda/{agenda_url}")
        for event in events:
            dict_event = dict(event)
            print(
                f"{dict_event['name']} op {dict_event['event_date']} in {dict_event['location']}"
            )

    def __execute_many_transaction_statement(
        self, create_statement, list_of_parameters=()
    ):
        c = self.conn.cursor()
        c.executemany(create_statement, list_of_parameters)
        self.conn.commit()

    def __execute_transaction_statement(self, create_statement, parameters=()):
        c = self.conn.cursor()
        c.execute(create_statement, parameters)
        self.conn.commit()
        return c.lastrowid

    def __execute_query(self, query, parameters=()):
        c = self.conn.cursor()
        c.row_factory = sqlite3.Row
        c.execute(query, parameters)
        return c.fetchall()

    def test_file_location(self):
        if not self.database_file.parent.exists():
            raise ValueError(
                f"Database file location {self.database_file.parent} does not exist"
            )
        if self.database_file.exists():
            if not self.database_overwrite:
                raise ValueError(
                    f"Database file {self.database_file} already exists, set overwrite=True to overwrite"
                )
            else:
                # Unlink verwijdert een bestand
                self.database_file.unlink()
                print("✅ Database already exists, deleted")
        if not self.database_file.exists():
            try:
                self.database_file.touch()
                print("✅ New database setup")
            except Exception as e:
                raise ValueError(
                    f"Could not create database file {self.database_file} due to error {e}"
                )


if __name__ == "__main__":
    my_path = Path(__file__).parent.resolve()
    project_root = my_path.parent.parent
    # Deze slashes komen uit de "Path" module. Dit is een module die je kan gebruiken
    # om paden te maken. Dit is handig omdat je dan niet zelf hoeft te kijken of je
    # een / (mac) of een \ (windows) moet gebruiken.
    database_path = project_root / "databases" / "event_calendar.db"
    database_generator = WP2DatabaseGenerator(
        database_path, overwrite=True, initial_data=True
    )
    database_generator.generate_database()
