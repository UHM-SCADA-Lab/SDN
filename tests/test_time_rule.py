# run "pytest" in the SDN directory to run all tests

from datetime import date
import time

from rules.time_rule import isValidTime

SECONDS_PER_MINUTE = 60
MINUTES_PER_HOUR   = 60
HOURS_PER_DAY      = 24
SECONDS_PER_HOUR   = SECONDS_PER_MINUTE * MINUTES_PER_HOUR
SECONDS_PER_DAY    = SECONDS_PER_HOUR * HOURS_PER_DAY

base_day           = date( 2023, 3, 17)

def get_base_timestamp():
    # defaults to Noon on March 17, 2023, a friday
    timestamp  = time.mktime(base_day.timetuple())
    timestamp += SECONDS_PER_HOUR * 12 # base time of noon
    return timestamp

def test_saturday():
    timestamp  = get_base_timestamp()
    timestamp += SECONDS_PER_DAY
    assert isValidTime( timestamp ) == False 

def test_sunday():
    timestamp  = get_base_timestamp()
    timestamp += 2 * SECONDS_PER_DAY
    assert isValidTime( timestamp ) == False
   
def test_monday():
    timestamp  = get_base_timestamp()
    timestamp += 3 * SECONDS_PER_DAY
    assert isValidTime( timestamp ) == True

def test_wednesday():
    timestamp  = get_base_timestamp()
    timestamp += 5 * SECONDS_PER_DAY
    assert isValidTime( timestamp ) == True

def test_friday():
    timestamp  = get_base_timestamp()
    assert isValidTime( timestamp ) == True
    
def test_early_times():
    timestamp  = get_base_timestamp()      # noon
    timestamp -= 12 * SECONDS_PER_HOUR;    # midnight
    print(time.localtime(timestamp))
    assert isValidTime( timestamp ) == False
    
    timestamp += 8 * SECONDS_PER_HOUR - 1; # 7:59:59 am
    assert isValidTime( timestamp ) == False

    timestamp += 1                         # 8 am
    assert isValidTime( timestamp ) == True

def test_late_times():
    timestamp  = get_base_timestamp()      # noon
    timestamp += 6 * SECONDS_PER_HOUR      # 6pm
    print(time.localtime(timestamp))
    assert isValidTime( timestamp ) == False

    timestamp -= 1                         # 5:59:59pm
    assert isValidTime( timestamp ) == True

    timestamp += 6 * SECONDS_PER_HOUR      # 11:59:59pm
    assert isValidTime( timestamp ) == False

def test_holiday():
    assert isValidTime( 0 ) == False # 0 = January 1st, 1970 - a holiday

