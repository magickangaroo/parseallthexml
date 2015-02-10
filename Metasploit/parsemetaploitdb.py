import psycopg2
import sys
pw=""
user=""

def connecttodb():
    try:
        con = psycopg2.connect(database='msf3', user=user, password=pw)
        cur = con.cursor()
        return cur

    except psycopg2.DatabaseError, e:
        print 'Error %s' % e
        sys.exit(1)

def gethosts(con):
    hosts = []

    query = "select id, address, mac, os_name, os_flavor, os_sp from hosts;"
    con.execute(query)
    rows = con.fetchall()
    for row in rows:
        host = {'id': row[0], 'address': row[1], 'mac': row[2], 'os_name': row[3], 'os_flavor': row[4], 'os_sp': row[5]}
        hosts.append(host)
    return hosts

def getservices(con):
    services = []
    query = "select id, host_id, port, proto, name, info from services;"
    con.execute(query)
    rows = con.fetchall()
    for row in rows:
        service = {'id': row[0], 'host_id': row[1], 'port': row[2], 'proto': row[3], 'name': row[4], 'info': row[5]}
        services.append(service)
    return services

def correlated(con):
    correlatedlist = []
    query = """SELECT hosts.id, hosts.address, hosts.mac, hosts.os_name, hosts.os_flavor, hosts.os_sp, services.host_id, services.port, services.proto, services.name, services.info
FROM services
INNER JOIN hosts
ON hosts.id = services.host_id;"""
    con.execute(query)
    rows = con.fetchall()
    for row in rows:

        joined = {'id': row[0], 'address': row[1], 'mac': row[2], 'os_name': row[3], 'os_flavor': row[4],
                  'os_sp': row[5], 'port': row[7], 'proto': row[8], 'name': row[9], 'info': row[10]}
        correlatedlist.append(joined)

    return correlatedlist

def printnicely(joined):
    listofips = []
    for entry in joined:
        if entry['address'] not in listofips:
            listofips.append(entry['address'])
            print "\n===Host %s===\nInformation found : Mac %s Detected OS %s Detected Flavour %s Detected " \
                  "Service Pack %s" % (entry['address'], entry['mac'], entry['os_name'], entry['os_flavor'], entry['os_sp'])
            print "Service Found - Port | Protocol | Name | Info"
            for service in joined:
                if service['address'] == entry['address']:
                    print "%i | %s | %s | %s" % \
                          (service['port'], service['proto'], service['name'], service['info'])




if __name__ == "__main__":
    connection = connecttodb()
    connection.execute('SELECT version()')
    ver = connection.fetchone()
    print ver

    hosts = gethosts(connection)
    services = getservices(connection)
    joined = correlated(connection)

    printnicely(joined)
