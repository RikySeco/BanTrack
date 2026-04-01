import requests
import configparser
import mysql.connector
import sqlite3
import logging
from systemd.journal import JournalHandler
from datetime import datetime, timedelta
import socket
from fail2ban.server.action import ActionBase

logger = logging.getLogger('db-write')
logger.setLevel(logging.ERROR)
logger.propagate = False
logger.addHandler(JournalHandler())
logger.addHandler(logging.FileHandler('/var/log/db-write-debug.log'))



class Action(ActionBase):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        dbconfig = configparser.ConfigParser()
        dbconfig.read('/etc/fail2ban/db.conf')

        if 'database' not in dbconfig:
            dbconfig_error = "ERRORE: File di configurazione corrotto o inesistente!"
            logger.error(dbconfig_error)
            #   Mail notify
            raise Exception(dbconfig_error)
        else:
            self.host = dbconfig['database']['host']
            self.user = dbconfig['database']['user']
            self.password = dbconfig['database']['password']
            self.database = dbconfig['database']['database']

    def sqlite_write(self, ip, jname, failures, bantime, matches, banned_at, unbanned_at, hostname, geo_fetched=0,
                     geo_continent_code=None,
                     geo_continent=None, geo_country_code=None, geo_country=None, geo_city=None, geo_latitude=None,
                     geo_longitude=None, geo_isp=None, geo_org=None, geo_as=None, geo_mobile=None, geo_proxy=None,
                     geo_hosting=None, error=None, status=1):

        retry_count = 0
        sqlite_cursor = None
        sqlite_conn = None

        try:
            sqlite_conn = sqlite3.connect('/var/lib/fail2ban/fallback.db')
            sqlite_cursor = sqlite_conn.cursor()
            query = """INSERT INTO ban_log (ip, jail_name, failures, banned_at, ban_duration, unbanned_at, matches,
                                            server_hostname, geo_fetched, geo_continent_code, geo_continent,
                                            geo_country_code, geo_country, geo_city, geo_latitude, geo_longitude,
                                            geo_isp, geo_org, geo_as, geo_mobile, geo_proxy, geo_hosting, retry_count,
                                            error_message, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

            sqlite_val = (ip, jname, failures, banned_at.isoformat(), bantime, unbanned_at.isoformat(), matches,
                          hostname, geo_fetched,
                          geo_continent_code, geo_continent, geo_country_code, geo_country, geo_city, geo_latitude,
                          geo_longitude, geo_isp, geo_org, geo_as, geo_mobile, geo_proxy, geo_hosting, retry_count,
                          error, status)

            sqlite_cursor.execute(query, sqlite_val)
            sqlite_conn.commit()

        except sqlite3.OperationalError as sqlite_error:
            logger.error(f"Errore nella scrittura del fallback: {sqlite_error}")
            #   Mail notify
            raise Exception(sqlite_error)

        finally:
            sqlite_cursor.close()
            sqlite_conn.close()

    def write_mysql(self, ip, jname, failures, bantime, matches, banned_at, unbanned_at, hostname, geo_continent_code,
                    geo_continent, geo_country_code, geo_country, geo_city, geo_latitude, geo_longitude, geo_isp,
                    geo_org,
                    geo_as, geo_mobile, geo_proxy, geo_hosting, status=1):

        mysql_conn = None
        mysql_cursor = None

        try:

            mysql_conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )

            mysql_cursor = mysql_conn.cursor()

            mysql_query = """
                          INSERT INTO ban_log (ip, jail_name, failures, banned_at, ban_duration, unbanned_at, matches,
                                               server_hostname, geo_continent_code, geo_continent, geo_country_code, \
                                               geo_country,
                                               geo_city, geo_latitude, geo_longitude, geo_isp, geo_org, geo_as, \
                                               geo_mobile, geo_proxy,
                                               geo_hosting, status)
                          VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) \
                          """

            values = (ip, jname, failures, banned_at, bantime, unbanned_at, matches, hostname, geo_continent_code,
                      geo_continent, geo_country_code, geo_country, geo_city, geo_latitude, geo_longitude, geo_isp,
                      geo_org, geo_as, geo_mobile, geo_proxy, geo_hosting, status)

            mysql_cursor.execute(mysql_query, values)
            mysql_conn.commit()

        except mysql.connector.Error as mysql_error:
            logger.error(f"Errore di scrittura di MySQL: {mysql_error}")
            error = str(mysql_error)
            self.sqlite_write(ip=ip, jname=jname, failures=failures, bantime=bantime, matches=matches, banned_at=banned_at,
                unbanned_at=unbanned_at, hostname=hostname, geo_fetched=1,
                geo_continent_code=geo_continent_code,
                geo_continent=geo_continent, geo_country_code=geo_country_code, geo_country=geo_country,
                geo_city=geo_city, geo_latitude=geo_latitude, geo_longitude=geo_longitude, geo_isp=geo_isp,
                geo_org=geo_org, geo_as=geo_as, geo_mobile=geo_mobile, geo_proxy=geo_proxy,
                geo_hosting=geo_hosting, error=error)

            raise Exception(error)

        finally:
            if mysql_cursor:
                mysql_cursor.close()
            if mysql_conn:
                mysql_conn.close()


    def ban(self,aInfo):

        ip = str(aInfo['ip'])
        jname = self._jail.name
        failures = int(aInfo['failures'])
        bantime = int(aInfo['bantime'])
        matches = str(aInfo['matches'])
        banned_at = datetime.fromtimestamp(aInfo['time'])
        unbanned_at = banned_at + timedelta(seconds=bantime)
        hostname = socket.gethostname()

        if hostname == "rikyseco":
            hostname = "Homeserver"
        else:
            hostname = "VPS"



        try:
            geo_response = requests.get(
                "http://ip-api.com/json/" + ip + "?fields=status,message,continent,continentCode,country,countryCode,city,lat,lon,isp,org,as,mobile,proxy,hosting")
            geo_response_json = geo_response.json()

            geo_status = geo_response_json['status']

            if geo_status == 'success':
                geo_continent_code = geo_response_json['continentCode']
                geo_continent = geo_response_json['continent']
                geo_country_code = geo_response_json['countryCode']
                geo_country = geo_response_json['country']
                geo_city = geo_response_json['city']
                geo_latitude = geo_response_json['lat']
                geo_longitude = geo_response_json['lon']
                geo_isp = geo_response_json['isp']
                geo_org = geo_response_json['org']
                geo_as = geo_response_json['as']
                geo_mobile = geo_response_json['mobile']
                geo_proxy = geo_response_json['proxy']
                geo_hosting = geo_response_json['hosting']

                self.write_mysql(ip, jname, failures, bantime, matches, banned_at, unbanned_at, hostname, geo_continent_code,
                            geo_continent, geo_country_code, geo_country, geo_city, geo_latitude, geo_longitude,
                            geo_isp,
                            geo_org, geo_as, geo_mobile, geo_proxy, geo_hosting)

            else:
                if geo_status == 'fail':
                    logger.error("Errore: Indirizzo IP non riconosciuto")
                    error = "Errore di ip API"
                    self.sqlite_write(ip=ip, jname=jname, failures=failures, bantime=bantime, matches=matches,
                                 banned_at=banned_at,
                                 unbanned_at=unbanned_at, hostname=hostname, error=error)
                    #   Mail notify
                    raise Exception(error)



        #   Case where there's an HTTP error
        except (requests.exceptions.ConnectionError, requests.exceptions.JSONDecodeError) as http_error:
            logger.error(f"Errore di connessione all'API: {http_error}")
            error = str(http_error)
            self.sqlite_write(ip=ip, jname=jname, failures=failures, bantime=bantime, matches=matches, banned_at=banned_at,
                         unbanned_at=unbanned_at, hostname=hostname, error=error)
            raise Exception(error)

    def unban(self,aInfo):

        mysql_conn = None
        mysql_cursor = None

        ip = str(aInfo['ip'])
        jname = self._jail.name

        try:

                mysql_conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )

            mysql_cursor = mysql_conn.cursor()

            mysql_update_query="""UPDATE ban_log SET status=0 
                                    WHERE ip=%s AND jail_name=%s AND status=1 
                                    ORDER BY banned_at DESC 
                                    LIMIT 1"""

            mysql_update_values = (ip, jname)

            mysql_cursor.execute(mysql_update_query, mysql_update_values)
            mysql_conn.commit()

        except mysql.connector.Error as mysql_update_error:
            logger.error(f"Errore di scrittura di MySQL: {mysql_update_error}")
            error = str(mysql_update_error)
            #   Fallback db write
            #   Mail notify
            raise Exception(error)

        finally:
            if mysql_cursor:
                mysql_cursor.close()
            if mysql_conn:
                mysql_conn.close()



















