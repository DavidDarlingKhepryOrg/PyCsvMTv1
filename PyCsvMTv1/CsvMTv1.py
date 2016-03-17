#!/usr/bin/python

import base64
import binascii
import csv
import hashlib
import io
import os
import sys

from threading import Thread
from time import time

newLine = '\n'

nbrOfThreads = 1

srcFiles = ['/home/data/voters/nc/ncvoter48.csv',
            '/home/data/voters/nc/ncvoter92.csv',
            '/home/data/voters/nc/ncvoter_Statewide.csv']

srcFileNdx = 0

tempFldr = 'temp'

hashColNames = ['last_name', 'registr_dt']
saltColNames = hashColNames

flushCount=1000
srcDelimiter=','
srcQuoting=csv.QUOTE_MINIMAL
srcEncoding='cp1252'
tgtDelimiter=','
tgtQuoting=csv.QUOTE_MINIMAL
tgtEncoding='cp1252'
rehashValues=True
rehashColName='ME998'
rehashColPrepend=True
rehashViaPBKDF2=False
rehashRounds=1000
newLine='\n'
isTestMode=False

totRowsSource = 0

# if temp folder doesn't exist
if not os.path.exists(tempFldr):
    # create it
    os.mkdir(tempFldr)

# initialize
# output files
ioTargets = []
for i in range(nbrOfThreads):
    ioTargets.append(io.open('temp/%02d.txt' % i, 'w', newline=''))

row = 0

# open source file for sequential reading
with io.open(srcFiles[srcFileNdx], 'r', newline='') as csvSrc:

    # beginning time hack
    bgnTime = time()

    # line-by-line
    for line in csvSrc:

        # first row
        # header row
        if row is 0:
            hdrRow = line

        # to which output file
        # should this line be written
        modulus = row % nbrOfThreads

        # output the header row
        # to the second and above files
        if row > 0 and row < nbrOfThreads:
            ioTargets[modulus].write(hdrRow)

        # output line to appropriate file
        ioTargets[modulus].write(line)

        # increment
        # row count
        row += 1

        # output a progress message at each modulus 0 of the flushCount
        if row > 0 and flushCount > 0 and row % flushCount is 0:
            # flush cached rows to disk
            for ioTarget in ioTargets:
                ioTarget.flush()

            # ending time hack
            endTime = time()
            # compute records/second
            seconds = endTime - bgnTime
            rcdsPerSec = row / seconds if seconds > 0 else 0
            # output progress message(s)
            message = 'Parsed: {:,} data rows in {:,.0f} seconds @ {:,.0f} records/second'.format(row, seconds, rcdsPerSec)
            print(message)

# flush cached rows to disk
for ioTarget in ioTargets:
    ioTarget.flush()

# ending time hack
endTime = time()
# compute records/second
seconds = endTime - bgnTime
rcdsPerSec = row / seconds if seconds > 0 else 0
# output end-of-processing message(s)
message = 'Parsed: {:,} data rows in {:,.0f} seconds @ {:,.0f} records/second'.format(row, seconds, rcdsPerSec)
print('-' * len(message))
print(message)
print('')

totRowsSource = row

# sys.exit(0)

# ========================================================================
# Hash a value according to the Data Submission Guide (DSG) specifications
# ========================================================================

def hash_via_dsg_specs_SHA256(srcValue='abc123',
                              hashRounds=1000,
                              srcEncoding='cp1252',
                              tgtEncoding='cp1252',
                              isTestMode=False,
                              isDebugMode=False):

    hashedResult = None
    saltValueHex = None

    if hashRounds > 0:

        if isDebugMode:
            print('initialValue : %s' % srcValue)
            print('rounds2HashIt: %d' % hashRounds)

        # clear and build up saltValue2bHashed variable
        saltValue2bHashed = ''.encode(encoding=srcEncoding)
        bytSrcValue = srcValue.encode(encoding=srcEncoding)
        saltValue2bHashed += bytSrcValue

        if isDebugMode:
            print('saltValue2bHashed: %s' % saltValue2bHashed)

        # hash the saltValue2bHashed variable
        # and convert it to a hexadecimal string,
        # which will become the salt for
        # the next hashing to be done below
        hash_salt = hashlib.sha256()
        hash_salt.update(saltValue2bHashed)
        salt_value = hash_salt.digest()
        saltValueHex = binascii.b2a_hex(salt_value).decode(srcEncoding)

        if isDebugMode:
            print('saltValueHex: %s' % saltValueHex)

        # clear and build up value2bHashed variable
        # by concatenating the srcValue with the saltValue
        value2bHashed = ''.encode(encoding=srcEncoding)
        bytSrcValue = (srcValue + saltValueHex).encode(encoding=srcEncoding)
        value2bHashed += bytSrcValue

        if isDebugMode:
            print('value2bHashed: %s' % value2bHashed)

        # hash the value2bHashed
        # for the number of rounds,
        # decoding the resulting
        # value via base64 encoding
        hash_algo = hashlib.sha256()
        hash_algo.update(value2bHashed)
        # hash the first round
        hash_value = hash_algo.digest()
        # hash the remaining rounds
        for _ in range(hashRounds-1):
            hash_value = hashlib.sha256(hash_value).digest()
        # translate the resulting hash into a Base64 string
        hashedResult = base64.b64encode(hash_value).decode(tgtEncoding)

        if isDebugMode:
            print('hashedResult: %s' % hashedResult)

        if isTestMode:
            print('')
            print("hash_value_via_dsg_specs_SHA256(srcValue='%s', rounds=%d)" % (srcValue, hashRounds))
            print('---------------------------------------------------------------')
            print('initialValue : %s' % srcValue)
            print('saltValueHex : %s' % saltValueHex)
            print('value2bHashed: %s' % value2bHashed.decode(srcEncoding))
            print('rounds2HashIt: %d' % hashRounds)
            print('hashedResult : %s' % hashedResult)

    return hashedResult, saltValueHex


def hash_via_pbkdf2_hmac(srcValue='abc123',
                         hashAlgorithm = 'sha256',
                         dklen=32,
                         hashRounds=1000,
                         srcEncoding='cp1252',
                         tgtEncoding='cp1252',
                         isTestMode=False):


    bytSrcValue = srcValue.encode(encoding=srcEncoding)

    # clear and build up saltValue2bHashed variable
    saltValue2bHashed = ''.encode(encoding=srcEncoding)
    saltValue2bHashed += bytSrcValue

    # clear and build up value2bHashed variable
    value2bHashed = ''.encode(encoding=srcEncoding)
    value2bHashed += bytSrcValue

    # hash the saltValue2bHashed variable
    # which will become the salt for
    # the pbkdf2_hmac hashing routine
    hash_salt = hashlib.sha256()
    hash_salt.update(saltValue2bHashed)
    salt_value = hash_salt.digest()
    # convert salt value to a hexadecimal string
    saltValueHex = binascii.b2a_hex(salt_value).decode(srcEncoding)

    # rehash the value2bHashed via the pbkdf2_hmac algorithm
    pbkdf2_hash_value = hashlib.pbkdf2_hmac(hashAlgorithm, value2bHashed, salt_value, hashRounds, dklen=dklen)

    # decode the resulting values using base64 encoding
    saltValue = binascii.b2a_hex(salt_value).decode(srcEncoding)
    hashedResult = base64.b64encode(pbkdf2_hash_value).decode(tgtEncoding)

    if isTestMode:
        print('')
        print("hash_via_pbkdf2_hmac(srcValue='%s', rounds=%d)" % (srcValue, hashRounds))
        print('---------------------------------------------------------------')
        print('initialValue : %s' % srcValue)
        print('saltValueHex : %s' % saltValueHex)
        print('value2bHashed: %s' % value2bHashed.decode(srcEncoding))
        print('rounds2HashIt: %d' % hashRounds)
        print('hashedResult : %s' % hashedResult)

    return hashedResult, saltValueHex


def hashTheFile(srcFileObj,
                srcFileName,
                flushCount=1000,
                srcDelimiter=',',
                srcQuoting=csv.QUOTE_MINIMAL,
                srcEncoding='cp1252',
                tgtDelimiter=',',
                tgtQuoting=csv.QUOTE_MINIMAL,
                tgtEncoding='cp1252',
                rehashValues=False,
                rehashColName='ME998',
                rehashColPrepend=True,
                hashColNames=None,
                saltColNames=None,
                rehashViaPBKDF2=False,
                rehashRounds=1000,
                newLine='\n',
                isTestMode=False):

    # instantiate a CSV DictReader object with
    # the incoming source delimiter and quoting parameters
    csvDictReader = csv.DictReader(srcFileObj, delimiter=srcDelimiter, quoting=srcQuoting)

    # obtain the field names from
    # the first row of the source file
    fieldNames = csvDictReader.fieldnames

    if rehashValues:
        # if the rehash column name
        # is NOT present in the field names
        if rehashColName not in fieldNames:
            # if prepend the
            # rehash column name
            if rehashColPrepend:
                # prepend the rehash column name
                # to the list of field names
                fieldNames.insert(0, rehashColName)
            # otherwise
            else:
                # append the rehash column name
                # to the list of field names
                fieldNames.append(rehashColName)

    tgtFileName, _ = os.path.splitext(srcFileName)
    tgtFileName += '.csv'

    tgtFileObj = io.open(tgtFileName, encoding=tgtEncoding, mode='w', newline='')

    csvDictWriter = csv.DictWriter(tgtFileObj, delimiter=tgtDelimiter, quoting=tgtQuoting, fieldnames=fieldNames)
    csvDictWriter.writeheader()

    # beginning time hack
    bgnTime = time()

    # initialize
    # row counter
    rowCount = 0

    # row-by-row
    for row in csvDictReader:

        # increment
        # row count
        rowCount += 1

        # trim all values in row
        for key, value in row.items():
            if value is not None:
                row[key] = value.strip()
            else:
                row[key] = value

        if rehashValues and hashColNames is not None and saltColNames is not None:
            # clear and build up saltValue2bHashed variable
            salt2bHashed = ''.encode(encoding=srcEncoding)
            for colName in saltColNames:
                try:
                    salt2bHashed += row[colName].encode(encoding=srcEncoding)
                except KeyError as err:
                    errStr = str(err)
                    sys.stderr.write('"saltColNames" option setting has an invalid column name: %s%s' % (errStr, newLine))
                    sys.stderr.write('Program will terminate immediately!%s' % newLine)
                    sys.exit(1)

            # clear and build up value2bHashed variable
            value2bHashed = ''.encode(encoding=srcEncoding)
            for colName in hashColNames:
                try:
                    value2bHashed += row[colName].encode(encoding=srcEncoding)
                except KeyError as err:
                    errStr = str(err)
                    sys.stderr.write('"hashColNames" option setting has an invalid column name: %s%s' % (errStr, newLine))
                    sys.stderr.write('Program will terminate immediately!%s' % newLine)
                    sys.exit(1)

            srcValue = value2bHashed.decode(encoding=srcEncoding)

            if isTestMode:
                print ('salt2bHashed : %s' % salt2bHashed.decode(encoding=srcEncoding))
                print ('value2bHashed: %s' % srcValue)

            # hash the source column's value
            # using the specified algorithm,
            # desired number of "rounds" and
            # the just-derived salt value above
            if rehashViaPBKDF2:
                hashedResult, saltValueHex = hash_via_pbkdf2_hmac(srcValue=srcValue,
                                                                  hashAlgorithm="sha256",
                                                                  dklen=32,
                                                                  hashRounds=rehashRounds,
                                                                  srcEncoding=srcEncoding,
                                                                  tgtEncoding=tgtEncoding,
                                                                  isTestMode=isTestMode)
                if isTestMode:
                    print('HASH_VIA_PBKDF2_HMAC_SHA256 :: value2bHashed: %s, saltValueHex: %s, hashedResult: %s' % (srcValue, saltValueHex, hashedResult))
            else:
                hashedResult, saltValueHex = hash_via_dsg_specs_SHA256(srcValue=srcValue,
                                                                       hashRounds=rehashRounds,
                                                                       srcEncoding=srcEncoding,
                                                                       tgtEncoding=tgtEncoding,
                                                                       isTestMode=isTestMode)
                if isTestMode:
                    print('HASH_VIA_DSG_SPECS_SHA256 :: value2bHashed: %s, saltValueHex: %s, hashedResult: %s' % (srcValue, saltValueHex, hashedResult))

            if isTestMode is True:
                print(value2bHashed, hashedResult)

            # overlay the specified column's
            # value with the resulting rehashed value,
            # remembering to base64 encode the rehashed value
            # for both readability and size reduction
            row[rehashColName] = hashedResult

        # output the row
        # to the target file
        csvDictWriter.writerow(row)

        # output a progress message at each modulus 0 of the flushCount
        if rowCount > 0 and flushCount > 0 and rowCount % flushCount is 0:
            # flush cached rows to disk
#             for ioTarget in ioTargets:
#                 ioTarget.flush()

            # ending time hack
            endTime = time()
            # compute records/second
            seconds = endTime - bgnTime
            rcdsPerSec = rowCount / seconds if seconds > 0 else 0
            # output progress message(s)
            message = '{} Parsed: {:,} data rows in {:,.0f} seconds @ {:,.0f} records/second'.format(srcFileName, rowCount, seconds, rcdsPerSec)
            print(message)

    # close the file(s)
    srcFileObj.close()
    tgtFileObj.close()

    # ending time hack
    endTime = time()
    # compute records/second
    seconds = endTime - bgnTime
    rcdsPerSec = rowCount / seconds if seconds > 0 else 0
    # output end-of-processing message(s)
    message = '{} Parsed: {:,} data rows in {:,.0f} seconds @ {:,.0f} records/second'.format(srcFileName, rowCount, seconds, rcdsPerSec)
    print('')
    print('-' * len(message))
    print(message)
    print('-' * len(message))

# instantiate
# threads list
threads = []

# beginning time hack
bgnTime = time()

# create a thread per file
# that is to be processed
for root, _, files in os.walk(tempFldr):
    for file in files:
        baseName, extension = os.path.splitext(file)
        if extension == '.txt':
            fileName = os.path.join(root, file)
            csvFile = io.open(fileName, encoding=srcEncoding, mode='r', newline='')
            t = Thread(target=hashTheFile,
                       args=[csvFile,
                             fileName,
                             flushCount,
                             srcDelimiter,
                             srcQuoting,
                             srcEncoding,
                             tgtDelimiter,
                             tgtQuoting,
                             tgtEncoding,
                             rehashValues,
                             rehashColName,
                             rehashColPrepend,
                             hashColNames,
                             saltColNames,
                             rehashViaPBKDF2,
                             rehashRounds,
                             newLine,
                             isTestMode])
            threads.append(t)

# start all of
# the threads
for t in threads:
    t.start()

# Wait for all of the
# threads to complete
# before exiting the program.
for t in threads:
    t.join()

# ending time hack
endTime = time()
seconds = endTime - bgnTime
avgRcdsPerSec = totRowsSource / seconds

message = '{} Parsed: {:,} data rows in {:,.0f} seconds @ {:,.0f} records/second'.format(srcFiles[srcFileNdx], totRowsSource, seconds, avgRcdsPerSec)
print('')
print('-' * len(message))
print(message)
print('-' * len(message))
