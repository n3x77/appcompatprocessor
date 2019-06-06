import settings
import logging
from ingest import Ingest
import re
from appAux import loadFile
from datetime import datetime
import ntpath
import sys 
import os 

logger = logging.getLogger(__name__)
# Module to ingest entries from the appcombat module of the APT-Scanner THOR and SPARK.
# The THOR/SPARK reports will be peraded from the txt files.

class Appcompat_THOR(Ingest):
    ingest_type = "appcompat_thor"
    # file_name_filter = '(?:\S*).(txt|log)$'
    file_name_filter = "(?:.*)(?:\/|\\\)(.*)\.txt$"

    def __init__(self):
        super(Appcompat_THOR, self).__init__()

    def checkMagic(self, file_name_fullpath):
        #TODO: Implement
        logger.error("Method not implemented")
        return True
    
    def getHostName(self, file_name_fullpath):
        # Reads the THOR/SPARK reports and extracts the hostname
        file_object = loadFile(file_name_fullpath)
        rows = file_object.read().splitlines()[1:]
        file_object.close()
        r_hostname = re.compile(r".*(SPARK|THOR): Info: MODULE: (Startup|Init) MESSAGE: Run on system: (?P<HOSTNAME>\S+)")
        assert (rows is not None)
        for r in rows:
            m = r_hostname.match(r)
            if m:
                hostname = m.group("HOSTNAME").upper() 
                logger.info("HOSTNAME found in THOR/SPARK report: %s" % hostname)
        
        if hostname is None:
            logger.error("Could not extract hostname from THOR/SPARK report file.")
        
        del file_object
        return hostname

    def processFile(self, file_fullpath, hostID, instanceID, rowsData):
        rowNumber = 0
        minSQLiteDTS = datetime(1, 1, 1, 0 ,0 ,0)
        maxSQLiteDTS = datetime(9999, 12, 31, 0, 0, 0)

        # Open the THOR/SPARK report file
        file_object = loadFile(file_fullpath)
        rows = file_object.read().splitlines()[1:]
        file_object.close()
        r_appcompatTHOR = re.compile(r".*MODULE: SHIMCache MESSAGE: (\S+) (.*)entry (FILE:|(.*) FILE:) (?P<FILE>.*) DATE: (?P<DATE>.*) TYPE: (?P<TYPE>.*) HIVEFILE: (?P<HIVE>.*) EXTRAS: (?P<EXTRAS>.*) (?P<EXEC>True|False) MD5: (?P<MD5>.*) (?P<SHA1>.*) (?P<SHA256>.*)")
        del file_object

        assert (rows is not None)
        for r in rows:
            m = r_appcompatTHOR.match(r)
            if m:
                try:

                    # Convert to timestmaps:
                    if m.group('DATE') != 'N/A':
                        tmp_date = datetime.strptime(m.group('DATE'), "%Y-%m-%d %H:%M:%S")
                    else:
                        tmp_date = minSQLiteDTS

                except Exception as e:
                    print("crap")
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    logger.info("Exception processing row (%s): %s [%s / %s / %s]" % (
                    e.message, unicode(ntpath.split(m.group('FILE'))[0]), exc_type, fname, exc_tb.tb_lineno))


                path, filename = ntpath.split(m.group('FILE'))
                namedrow = settings.EntriesFields(HostID=hostID, 
                EntryType=settings.__APPCOMPAT__, 
                RowNumber=rowNumber,
                LastModified =tmp_date,
                LastUpdate = tmp_date,
                FilePath = unicode(path),
                FileName = unicode(filename),
                ExecFlag=str(m.group('EXEC')),
                SHA1 = unicode(m.group('SHA1')),
                InstanceID=instanceID)

                rowsData.append(namedrow)
                rowNumber += 1