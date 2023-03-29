import time
import holidays

def isValidTime( unixTimestamp ):
    # returns TRUE  if current day a weekday 
    #           AND if current time is after 8AM HST and before 6PM HST
    #           AND if current day isn't a government holiday
    # returns FALSE otherwise

    currTime = time.localtime( unixTimestamp )
    
    # check if current day isn't a weekday
    # MONDAY = 0, SATURDAY = 5, SUNDAY = 6
    weekday = currTime.tm_wday
    if weekday >= 5:
        print("Today isn't a weekday")
        return False
    
    # check if current time is before 8AM or after 6PM
    # 8AM when hour = 8  -> time is 8:XX AM
    # 6PM when hour = 18 -> time is 6:XX PM
    hour = currTime.tm_hour
    if hour < 8 or hour >= 18:
        print("The current hour isn't during normal work hours!")
        return False

    # check if current day is a holiday
    hawaii_holidays = holidays.country_holidays('US', subdiv='HI')
    if unixTimestamp in hawaii_holidays:
        print("Today is a holiday!")
        return False
    
    return True
