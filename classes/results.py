__author__ = 'adz'
import sqlite3
import uuid
import math

class Results:
    def __init__(self, target, port, protocol, logging, **kwargs):
        self.target = target
        self.protocol = protocol
        self.port = port
        self.findingfound = False
        self.logging = logging
        for key, value in kwargs.iteritems():
            if key == "gluedb":
                self.gluedb = value


    def createdbobject(self):
        self.conn = sqlite3.connect(self.gluedb)
        self.c = self.conn.cursor()

    def commitdb(self):
        self.conn.commit()
        self.conn.close()

    def insertfinding(self, findingtitle, findingguid):

        if self.findingfound:
            #only want to do this if theres a finding right?
            self.subjectguid = uuid.uuid4()
            self.logging.info("[I] Inserting New - %s (%s/%s)" % (self.target, self.protocol, self.port))
            querysubject = "insert into Subjects('SubjectGuid', 'Name') values ('%s','%s (TCP/%s)')" % \
                               (self.subjectguid, self.target, self.port)

            query = "insert into Findings('FindingGuid','WriteUpGuid','Title','Subject','DefaultSeverityId','SeverityId'," \
                        "'Tester','Status','ReportNotes','InternalNotes','QaNotes','QaFlag')"
            #is this a single finding or part of a list?

            if len(self.findingtextlist) == 0:
                #not part of a list

                query += ' values ("%s","%s","%s","%s", "NULL","4","%s","1", "%s","","","0")' % \
                        (uuid.uuid4(), findingguid, findingtitle, self.subjectguid, self.tester,
                         self.findingtext)


            elif len(self.findingtextlist) != 0:
                # part of a list, we may now have multiple finding texts to merge

                query += ' values ("%s","%s","%s","%s", "NULL","4","%s","1", "%s","","","0")' % \
                        (uuid.uuid4(), findingguid, findingtitle, self.subjectguid, self.tester,
                         '\n'.join(self.findingtextlist))
            self.c.execute(querysubject)
            self.c.execute(query)





