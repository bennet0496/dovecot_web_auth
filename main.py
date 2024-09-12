from fastapi import FastAPI, Response, status
from pydantic import BaseModel
import pymysql.cursors
import passlib.hash
import socket
import geoip2.database, geoip2.errors
import struct
app = FastAPI()

geoip = "./"

local_networks = {
    "Network 1":                 ("192.0.2.0", 24),
    "Network 2":          ("198.51.100.0", 24),
    "Network 3":             ("203.0.113.0", 24),
    "Network 4":    ("192.168.4.0", 24),
    "Network 5":                   ("192.168.3.0", 24),
    "Wifi Network 1":                  ("192.168.1.0", 24),
    "Wifi Network 2":     ("192.168.0.0", 24),
}

@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}


class AuthRequest(BaseModel):
    username: str
    password: str
    service: str
    remote_ip: str

@app.post("/auth", status_code=status.HTTP_400_BAD_REQUEST)
async def auth(request: AuthRequest, response: Response):
    success = False
    connection = pymysql.connect(host='db.example.com', user='mailserver',
                                 password='password', db='mail')
    with (connection):
        connection.autocommit(True)
        with connection.cursor() as cursor:
            sql = "SELECT * FROM app_passwords WHERE uid = %s"
            cursor.execute(sql, (request.username,))
            for row in cursor.fetchall():
                if passlib.hash.ldap_sha512_crypt.verify(request.password, row[2]):
                    rdns = socket.gethostbyaddr(request.remote_ip)[0] or ""
                    location = ""
                    isp = ""
                    # TODO: IPv6?
                    ip_int = struct.unpack("!L", socket.inet_aton(request.remote_ip))[0]
                    for net in local_networks.items():
                        net_int = struct.unpack("!L", socket.inet_aton(net[1][0]))[0]
                        mask = 0xffffffff << (32-net[1][1])
                        if net_int & mask == ip_int & mask:
                            location = net[0]
                            isp = "local network"
                            break
                    else:
                        with geoip2.database.Reader(geoip + 'GeoLite2-City.mmdb') as city_reader, \
                                geoip2.database.Reader( geoip + 'GeoLite2-ASN.mmdb') as asn_reader:
                            try:
                                city = city_reader.city(request.remote_ip)
                                isp = asn_reader.asn(request.remote_ip).autonomous_system_organization
                                location = str(city.city.name) + ", " + str(city.subdivisions.most_specific.name) + ", " + str(city.country.name)
                            except geoip2.errors.AddressNotFoundError:
                                pass
                    sql = "INSERT INTO log(id, pwid, service, src_ip, src_rdns, src_loc, src_isp, timestamp) VALUES (NULL, %s, %s, %s, %s, %s, %s, UTC_TIMESTAMP(3))"
                    print(cursor.execute(sql, (row[0], request.service, request.remote_ip, rdns, location, isp)))
                    success = True
                    break
    response.status_code = status.HTTP_200_OK if success else status.HTTP_401_UNAUTHORIZED
    return {"success": success}