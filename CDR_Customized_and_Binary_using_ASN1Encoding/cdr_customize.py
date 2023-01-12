import os
import glob
import errno
import shutil
import timeit
import asn1tools
import re
##############################################################################
# author      = 'Hashan Wijeratne'                                           # 
# version     = 'v1.7'                                                       #
# updates                                                                    #
#       v1.1) ASN1 Tag change                                                #
#       v1.2) Data Time format change and msisdn encoding format change      #
#       v1.3) empty line issue resolved                                      #
#       v1.4) Destination MSISDN prefix remove for emse 7050/7051/7052       #
#       v1.5) event 8 prefix remove and remove prefix 7850/7851/7852         #
#             incoming esme                                                  # 
#       v1.6) SMPP Special Characters replacei                               #
#        v1.7) CDR special character read issue fixed                        #  
# description = 'Customized prime CDR and encode into ASN1 format'           #
##############################################################################

# define log path
dir = "/home/devops/"

# log files and directories
logfiles = dir + "*.log"
backup_logs = dir + "backup_logs"
bin_logs = dir + "bin_logs"

# asn.1 encode file using  foo Protocol
foo = asn1tools.compile_files('foo.asn')


# map ton key values
def tonDesc(ton):
    tonval = {
        '0': 'unknown',
        '1': 'international',
        '2': 'national',
        '3': 'network',
        '4': 'short',
        '5': 'alpha',
        '6': 'abbreviated'
    }
    return tonval.get(ton, '')


# map npi keys
def npiKey(npi):
    npival = {
        '0': '0',
        '1': '1',
        '3': '3',
        '4': '4',
        '6': '6',
        '8': '8',
        '9': '9',
        '10': '10',
        '13': '14'
    }
    return npival.get(npi, '')


# map status key values
def statusDesc(status):
    statusval = {
        '5': 'delivered',
        '2': 'expired',
        '11': 'deleted',
        '13': 'replaced',
        '8': 'submitted',
        '9': 'rejected',
        '6': 'incomplete-delivery',
        '7': 'undeliverable'
    }
    return statusval.get(status, '')


# Check MSISDN Prefix
def checkPrefix(num):
    # first 6 numbers of msisdn
    prefix = num[:6]

    # check prefix
    if prefix == '507160' or prefix == '507198' or prefix == '507197' or prefix == '507196':
        msisdn = msisdnChange(num)

    else:
        msisdn = num

    return msisdn


# Change MSISDN related to ESME
def msisdnChange(num):
    # remove prefix
    msisdn = num[:3] + num[6:]

    return msisdn


# Destination MSISDN prefix check
def destMsisdn(num, esme, event):
    if int(event) == 8 and len(num) == 14:
        msisdn = checkPrefix(num)

    elif esme == '7050' or esme == '7051' or esme == '7052' or esme == '7850' or esme == '7851' or esme == '7852':
        msisdn = checkPrefix(num)

    else:
        msisdn = num

    return msisdn


# date format change
def dateFormat(date):
    dateSplit = date.split("-")
    year = list(dateSplit[0])
    yy1 = year[2] + year[3]
    yy = hex(int(yy1))[2:]
    mm = hex(int(dateSplit[1]))[2:]
    dd = hex(int(dateSplit[2]))[2:]

    if len(yy) == 1:
        y = str(0) + yy
    else:
        y = yy

    if len(mm) == 1:
        m = str(0) + mm
    else:
        m = mm

    if len(dd) == 1:
        d = str(0) + dd
    else:
        d = dd

    return y + m + d


# time format change
def timeFormat(time):
    timeSplit = time.split(":")

    hh = hex(int(timeSplit[0]))[2:]
    mm = hex(int(timeSplit[1]))[2:]
    ss = hex(int(timeSplit[2]))[2:]

    if len(hh) == 1:
        h = str(0) + hh
    else:
        h = hh

    if len(mm) == 1:
        m = str(0) + mm
    else:
        m = mm

    if len(ss) == 1:
        s = str(0) + ss
    else:
        s = ss

    return h + m + s


# check origLASN
def checkOrig(event, esme, source, dest):
    if int(event) == 8 and int(source) == 1:
        return esme

    elif int(event) == 5 and int(source) == 1 and int(dest) == 0:
        return esme

    else:
        return ''


# check recipLASN
def checkRecip(event, esme, source, dest):
    if int(event) == 5 and int(source) == 0 and int(dest) == 1:
        return esme

    else:
        return ''


# execute files one by one inside of directory
for file in glob.glob(logfiles):
    try:
        # read log file and handle special characters
        infile = open(file, 'r', encoding="utf-8", errors="replace")

        # remove file format from log path
        filepath = os.path.splitext(file)[0]

        # get file name from log path
        splitfilepath = filepath.strip().split("/")
        filename = splitfilepath[-1]

        # check file is empty or not
        if os.stat(file).st_size != 0:
            # create temporary customize cdr file
            tmpfile = open(filename + "_cus.log", "w+")
            # execute line by line from execute file
            for line in infile:
                # read line, add into array list
                x = line.strip().split(",")
              
                # check empty lines
                if len(x) != 1:
                    # date time split
                    if x[1] != '':
                        datetime_accept = x[1].split(" ")
                        accept_date = datetime_accept[0]
                        accept_time = datetime_accept[1]
                    else:
                        accept_date = ''
                        accept_time = ''

                    if x[14] != '':
                        datetime_expire = x[14].split(" ")
                        expire_date = datetime_expire[0]
                        expire_time = datetime_expire[1]

                    else:
                        expire_date = ''
                        expire_time = ''

                    if int(x[0]) != 1:
                        if int(x[0]) != 3:
                            if int(x[0]) != 10:
                                # write into tmp customize cdr file
                                tmpfile.write(
                                    x[17] + "," + x[18] + "," + x[15] + "," + x[2] + "," + x[3] + "," + x[19] + "," + x[
                                        20] + "," + x[
                                        15] + "," + x[4] + "," + x[5] + "," + accept_date + "," + accept_time + "," + x[
                                        0] + "," + expire_date + "," + expire_time + "," + x[13] + "," + x[46] + "," +
                                    x[
                                        2] + "," + accept_date + "," + accept_time + "," + '0' + "," + x[45] + "," + x[
                                        12] + "," + x[
                                        49] + "," + '0' + "," + x[43] + "," + x[44] + "\n")

            # read temporary customize cdr file
            tmpfile = open(filename + "_cus.log", 'r')

            # create binary file
            binfile = open(filename + "_bin", 'w+b')

            # read temp cdr file
            for line1 in tmpfile:
                event = line1.strip().split(",")
                # cdr encode ASN.1 format
                encoded = foo.encode('CallDetailRecord', {
                    'origAddress': {'ton': tonDesc(event[0]), 'npi': int(npiKey(event[1])), 'pid': int(event[2]),
                                    'msisdn': re.sub('[^a-zA-Z0-9\n\.]', '',event[3]), 'msisdnUTF8': re.sub('[^a-zA-Z0-9\n\.]', '',event[4])},
                    'recipAddress': {'ton': tonDesc(event[5]), 'npi': int(npiKey(event[6])), 'pid': int(event[7]),
                                     'msisdn': destMsisdn(re.sub('[^a-zA-Z0-9\n\.]', '',event[8]), event[21], event[12]),
                                     'msisdnUTF8': destMsisdn(re.sub('[^a-zA-Z0-9\n\.]', '',event[9]), event[21], event[12])},
                    'msisdn': event[3],
                    'submitDate': bytearray(dateFormat(event[10]), 'utf-8'),
                    'submitTime': bytearray(timeFormat(event[11]), 'utf-8'),
                    'status': statusDesc(event[12]),
                    'terminDate': bytearray(dateFormat(event[13]), 'utf-8'),
                    'terminTime': bytearray(timeFormat(event[14]), 'utf-8'),
                    'lengthOfMessage': int(event[15]),
                    'prioIndicator': bool(event[16]),
                    'orglSubmitDate': bytearray(dateFormat(event[18]), 'utf-8'),
                    'orglSubmitTime': bytearray(timeFormat(event[19]), 'utf-8'),
                    'portNumber': int(event[20]),
                    'origLASN': checkOrig(event[12], event[21], event[25], event[26]),
                    'recipLASN': checkRecip(event[12], event[21], event[25], event[26]),
                    'origMsgID': event[22],
                    'deliveryAttempts': int(event[23]),
                    'msgError': int(event[24])
                })
                binfile.write(encoded)
            shutil.move(filename + "_bin", bin_logs)
            shutil.move(file, backup_logs)
            os.remove(filename + "_cus.log")

        # if file is empty
        else:
            binfile = open(filename + "_bin", 'w+b')
            shutil.move(filename + "_bin", bin_logs)
            shutil.move(file, backup_logs)

    except IOError as exc:
        if exc.errno != errno.EISDIR:
            raise
