import settings
import logging
from ingest import Ingest
import re
from appAux import loadFile
from datetime import datetime

logger = logging.getLogger(__name__)
# Module to ingest entries from the appcombat module of the APT-Scanner THOR and SPARK.
# The THOR/SPARK reports will be peraded from the txt files.

class Appcompat_THOR(Ingest):
    ingest_type = "appcompat_thor"
    file_name_filter = '(?:\S*).(txt|log)$'

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
                logger.debug("HOSTNAME found in THOR/SPARK report: %s" % hostname)
        
        if hostname is None:
            logger.error("Could not extract hostname from THOR/SPARK report file.")
        
        del file_object
        return hostname

    def processFile(self, file_fullpath, hostID, instanceID, rowsData):
        rowNumber = 0
        # Open the THOR/SPARK report file
        file_object = loadFile(file_name_fullpath)
        rows = file_object.read().splitlines()[1:]
        file_object.close()
        del file_object

        r_amcacheTHOR = re.compile(r".*MODULE: (Amcache) MESSAGE: (\S+) (.*)entry (FILE:|(.*) FILE:) (?P<FILE>.*) SHA1: (?P<SHA1>\w+) SIZE: (?P<SIZE>(None|\d)) DESC: (?P<DESC>.*) FIRST_RUN: (?P<FIRST_RUN>.*) CREATED: (?P<CREATED>.*) PRODUCT: (?P<PRODUCT>.*) COMPANY: (?P<COMPANY>.*)")
        
        assert (rows is not None)
        for r in rows:
            m = r_amcacheTHOR.match(r)
            if m:
                namedrow = settings.EntriesFields(HostID=hostID, EntryType=settings.__APPCOMPAT__, RowNumber=rowNumber,
                FirstRun = m.group('FIRST_RUN'), Created= m.group('CREATED'),
                FilePath = m.group('FILE'),
                FileName = m.group('FILE'),
                SHA1 = m.group('SHA1'),
                Size = m.group('SIZE'),
                Product = m.group('PRODUCT'),
                Company = m.group('COMPANY'),
                FileDescription = m.group('DESC'),
                InstanceID=instanceID)
                
                rowsData.append(namedrow)
                rowNumber += 1
            else:
                logger.warning("Entry regex failed for: %s - %s" (hostID, r))
