# Dovecot Web Authenticator for App Passwords

This projects purpose is to provide a small App Passwords 
Web API for Dovecot to authenticate against. It is designed to
interoperate with the Roundcube Plugin `mpipks/imap_apppasswd`
while simultaneously providing audit logging similar to 
[`dovecot_badclients`](https://github.com/bennet0496/dovecot_badclients).

While it is possible to implement App Password with a normal SQL
passdb in Dovecot. It becomes more difficult if precise last-login
tracking is desired, as it is only reliably possible to get Dovecot
to run a post-login script for the IMAP (and POP3) service. If an MTA 
is connected via SASL, these login would not be tracked.

# Requirements and Setup

To get this work you'll need the **Dovecot LUA Plugin**, a **Python runtime**,
a **Redis-compatible server**, a **MySQL-compatible Database** and the **MaxMind
GeoLite2** City and ASN MMDB-Databases. 

You'll find the Python requirements in the `requirements.txt`. Either install 
them to your system or create a virtual environment with `venv` or `conda`.

It is recommended to use [KeyDB](https://docs.keydb.dev/) (as Redis Drop-in) 
and MariaDB (as MySQL Drop-in)

```bash
apt install dovecot-auth-lua python3-venv python3-systemd \
  keydb-server mariadb-server geoipupdate
  
cd /path/to/install/to
git clone ...

cd dovecot_web_auth

python3 -m venv --system-site-packages --symlinks .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration
Before stating it you will need to configure you database and set up your 
`config.toml`.

First get a GeoLite License and configure it according to the [MaxMind Docs](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).

Then make sure Redis/KeyDB, MariaDB and the GeoIP Updater are running
```bash
systemctl enable --now keydb-server.service
systemctl enable --now mariadb.service
systemctl enable --now geoipupdate.timer
```

Then seed the database (or import the old dump)
```sql
CREATE DATABASE mail_auth;
GRANT USAGE ON *.* TO `mailserver`@`localhost` IDENTIFIED BY 'password123';
GRANT USAGE ON *.* TO `roundcube`@`webmail.example.com` IDENTIFIED BY 'password123';

GRANT SELECT ON `mail_auth`.`log` TO `roundcube`@`webmail.example.com`;
GRANT SELECT, SHOW VIEW ON `mail_auth`.`app_passwords_with_log` TO `roundcube`@`webmail.example.com`;
GRANT SELECT, INSERT, UPDATE (`comment`), DELETE ON `mail_auth`.`app_passwords` TO `roundcube`@`webmail.example.com`;

GRANT SELECT ON `mail_auth`.`app_passwords` TO `mailserver`@`localhost`;
GRANT SELECT, INSERT ON `mail_auth`.`log` TO `mailserver`@`localhost`;
```

Then import the DDL (or previous dump)
```bash
mysql mail_auth < database/DDL.sql
```

Now set up the `config.toml`. An example of the available options is in
`config.toml.dist`. A minimal configuration could be the following
```toml
[database]
dsn = "mysql+pymysql://user:pass@host/mail"
[ldap]
host = "ldap.example.com"
basedn = "ou=users,dc=example,dc=com"
[audit]
audit_result_success = "unknown"
[audit.maxmind]
city = "./mmdb/GeoLite2-City.mmdb"
asn = "./mmdb/GeoLite2-ASN.mmdb"
[audit.lists]
ip_networks = "/path/to/list/..."
reverse_hostname = "/path/to/list/..."
network_name = "/path/to/list/..."
network_cc = "/path/to/list/..."
entities = "/path/to/list/..."
as_numbers = "/path/to/list/..."
as_names = "/path/to/list/..."
as_cc = "/path/to/list/..."
geo_location_ids = "/path/to/list/..."
```

The list setup will be detailed below.

## Running
To run the API use `uvicorn` or run `main.py` directly
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --workers 4
```
If the `config.toml` is not in your current working directory, set the environment variable 
`CONFIG_PATH` to the path to the file.

To run it as a system service, you can use the `dovecot-web-auth.service`
SystemD unit as an example

## Setup Dovecot

This Web API can be used for App Password authentication, as well as just for auditing akin to 
[`dovecot_badclients`](https://github.com/bennet0496/dovecot_badclients). To integrate this functionality
into Dovecot, two small LUA Scripts are used.

### Auth setup
Create a passdb with the following config
```
passdb {
  driver = lua
  args = file=/etc/dovecot/auth.lua blocking=yes
  skip = authenticated
}
```
You may want to reconfigure your real passdb, to only allow its usages from certain hosts
like a Webmailer with 2 Factor. Add the following to that passdb
```
...
passdb {
  ...
  # Replace with Roundcube IP
  override_fields = allow_nets=1.2.3.4/32
  ...
}
...
```

### Audit setup
If you just need auditing without App Password, e.g. in a transitional period, add the following as
your last passdb
```
passdb {
  driver = lua
  args = file=/etc/dovecot/audit.lua blocking=yes
  skip = unauthenticated
}
```
And add `result_success = continue-ok` to any previous passdb you want auditing for
```
passdb {
...
  result_success = continue-ok
}
```

# Using the lists

With the `[audit.lists]` config section you set up the path to lists that are parsed during auditing.
If an entry matches, the login request is denied. However, baring the service limitation none of lists
will ever (with a few exceptions) block request from IPs not globally reachable by [iana-ipv4-special-registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml) 
(for IPv4) or [iana-ipv6-special-registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml) 
(for IPv6). These exceptions are as follows
- 100.64.0.0/10 is not considered private
- For IPv4-mapped IPv6-addresses the result is determined by the semantics of the underlying IPv4 addresses

I.e. everything that is considered private by [`ipaddress._BaseAddress.is_private`](https://docs.python.org/3.12/library/ipaddress.html#ipaddress.IPv4Address.is_private).

### `asn.deny.lst`
List of literal Autonomous System Numbers to block 

E.g. 
```
# Vodafone, DE
AS3209
```

### Autonomous System Names: `as_names`
List of Python Regular Expressions matched against IPWhois' `as_desc` and MaxMind's `as_org`.
The IPWhois `as_desc` consists of the AS', first line of `descr` and the CC when running WHOIS 
against the AS. And MaxMind's `as_org` is similar or just the human-readable company name.

E.g.`whois AS3209`
```
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See https://apps.db.ripe.net/docs/HTML-Terms-And-Conditions

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to 'AS3209 - AS3353'

as-block:       AS3209 - AS3353
descr:          RIPE NCC ASN block
remarks:        These AS Numbers are assigned to network operators in the RIPE NCC service region.
mnt-by:         RIPE-NCC-HM-MNT
created:        2018-11-22T15:27:19Z
last-modified:  2018-11-22T15:27:19Z
source:         RIPE

% Information related to 'AS3209'

% Abuse contact for 'AS3209' is 'abuse.de@vodafone.com'

aut-num:        AS3209
as-name:        VODANET
org:            ORG-MAT1-RIPE
descr:          International IP-Backbone of Vodafone
descr:          Duesseldorfer Strasse 15
descr:          D-65760 Eschborn
descr:          Germany
descr:          http://www.vodafone.de
```
Becomes `VODANET International IP-Backbone of Vodafone, DE`, for IPWhois. And MaxMind outputs
`Vodafone GmbH`.

Each line needs to be a valid Python Regular expression that need to match the entire 
description e.g. `VODANET.*` or `.*Vodafone.*` for `VODANET International IP-Backbone of Vodafone, DE`

### Network and AS Country Codes: `as_cc` and `network_cc`
List [ISO 3166-2 country codes](https://www.iso.org/iso-3166-country-codes.html), associated to the Autonomous System or Network. One per line.

<details>

| CC | Country                           | CC | Country                                    | CC | Country                                    | CC | Country                            |
|:--:|:----------------------------------|:--:|:-------------------------------------------|:--:|:-------------------------------------------|:--:|:-----------------------------------|
| `AD` | Andorra                           | `EG` | Egypt                                      | `LB` | Lebanon                                    | `RO` | Romania                            |
| `AE` | United Arab Emirates              | `EH` | Western Sahara                             | `LC` | Saint Lucia                                | `RS` | Serbia                             |
| `AF` | Afghanistan                       | `ER` | Eritrea                                    | `LI` | Liechtenstein                              | `RU` | Russian Federation                 |
| `AG` | Antigua & Barbuda                 | `ES` | Spain                                      | `LK` | Sri Lanka                                  | `RW` | Rwanda                             |
| `AI` | Anguilla                          | `ET` | Ethiopia                                   | `LR` | Liberia                                    | `SA` | Saudi Arabia                       |
| `AL` | Albania                           | `FI` | Finland                                    | `LS` | Lesotho                                    | `SB` | Solomon Islands                    |
| `AM` | Armenia                           | `FJ` | Fiji                                       | `LT` | Lithuania                                  | `SC` | Seychelles                         |
| `AN` | Netherlands Antilles              | `FK` | Falkland Islands (Malvinas)                | `LU` | Luxembourg                                 | `SD` | Sudan                              |
| `AO` | Angola                            | `FM` | Micronesia, Federated States Of            | `LV` | Latvia                                     | `SE` | Sweden                             |
| `AQ` | Antarctica                        | `FO` | Faroe Islands                              | `LY` | Libyan Arab Jamahiriya                     | `SG` | Singapore                          |
| `AR` | Argentina                         | `FR` | France                                     | `MA` | Morocco                                    | `SH` | St. Helena                         |
| `AS` | American Samoa                    | `GA` | Gabon                                      | `MC` | Monaco                                     | `SI` | Slovenia                           |
| `AT` | Austria                           | `GB` | United Kingdom                             | `MD` | Moldova, Republic Of                       | `SJ` | Svalbard & Jan Mayen Islands       |
| `AU` | Australia                         | `GD` | Grenada                                    | `ME` | Montenegro                                 | `SK` | Slovakia (Slovak Republic)         |
| `AW` | Aruba                             | `GE` | Georgia                                    | `MF` | Saint Martin                               | `SL` | Sierra Leone                       |
| `AX` | Aland Islands                     | `GF` | French Guiana                              | `MG` | Madagascar                                 | `SM` | San Marino                         |
| `AZ` | Azerbaijan                        | `GG` | Guernsey                                   | `MH` | Marshall Islands                           | `SN` | Senegal                            |
| `BA` | Bosnia & Herzegovina              | `GH` | Ghana                                      | `MK` | Macedonia, The Former Yugoslav Republic Of | `SO` | Somalia                            |
| `BB` | Barbados                          | `GI` | Gibraltar                                  | `ML` | Mali                                       | `SR` | Suriname                           |
| `BD` | Bangladesh                        | `GL` | Greenland                                  | `MM` | Myanmar                                    | `ST` | Sao Tome & Principe                |
| `BE` | Belgium                           | `GM` | Gambia                                     | `MN` | Mongolia                                   | `SV` | El Salvador                        |
| `BF` | Burkina Faso                      | `GN` | Guinea                                     | `MO` | Macau                                      | `SY` | Syrian Arab Republic               |
| `BG` | Bulgaria                          | `GP` | Guadeloupe                                 | `MP` | Northern Mariana Islands                   | `SZ` | Swaziland                          |
| `BH` | Bahrain                           | `GQ` | Equatorial Guinea                          | `MQ` | Martinique                                 | `TC` | Turks & Caicos Islands             |
| `BI` | Burundi                           | `GR` | Greece                                     | `MR` | Mauritania                                 | `TD` | Chad                               |
| `BJ` | Benin                             | `GS` | South Georgia & The South Sandwich Islands | `MS` | Montserrat                                 | `TF` | French Southern Territories        |
| `BM` | Bermuda                           | `GT` | Guatemala                                  | `MT` | Malta                                      | `TG` | Togo                               |
| `BN` | Brunei Darussalam                 | `GU` | Guam                                       | `MU` | Mauritius                                  | `TH` | Thailand                           |
| `BO` | Bolivia                           | `GW` | Guinea-Bissau                              | `MV` | Maldives                                   | `TJ` | Tajikistan                         |
| `BR` | Brazil                            | `GY` | Guyana                                     | `MW` | Malawi                                     | `TK` | Tokelau                            |
| `BS` | Bahamas                           | `HK` | Hong Kong                                  | `MX` | Mexico                                     | `TL` | Timor-Leste                        |
| `BT` | Bhutan                            | `HM` | Heard & Mc Donald Islands                  | `MY` | Malaysia                                   | `TM` | Turkmenistan                       |
| `BV` | Bouvet Island                     | `HN` | Honduras                                   | `MZ` | Mozambique                                 | `TN` | Tunisia                            |
| `BW` | Botswana                          | `HR` | Croatia (Hrvatska)                         | `NA` | Namibia                                    | `TO` | Tonga                              |
| `BY` | Belarus                           | `HT` | Haiti                                      | `NC` | New Caledonia                              | `TR` | Turkey                             |
| `BZ` | Belize                            | `HU` | Hungary                                    | `NE` | Niger                                      | `TT` | Trinidad & Tobago                  |
| `CA` | Canada                            | `ID` | Indonesia                                  | `NF` | Norfolk Island                             | `TV` | Tuvalu                             |
| `CC` | Cocos (Keeling) Islands           | `IE` | Ireland                                    | `NG` | Nigeria                                    | `TW` | Taiwan                             |
| `CD` | Congo, Democratic Republic Of The | `IL` | Israel                                     | `NI` | Nicaragua                                  | `TZ` | Tanzania, United Republic Of       |
| `CF` | Central African Republic          | `IM` | Isle Of Man                                | `NL` | Netherlands                                | `UA` | Ukraine                            |
| `CG` | Congo                             | `IN` | India                                      | `NO` | Norway                                     | `UG` | Uganda                             |
| `CH` | Switzerland                       | `IO` | British Indian Ocean Territory             | `NP` | Nepal                                      | `UM` | United States Minor Outlying Islands|
| `CI` | Cote D’Ivoire                     | `IQ` | Iraq                                       | `NR` | Nauru                                      | `US` | United States                      |
| `CK` | Cook Islands                      | `IR` | Iran (Islamic Republic Of)                 | `NU` | Niue                                       | `UY` | Uruguay                            |
| `CL` | Chile                             | `IS` | Iceland                                    | `NZ` | New Zealand                                | `UZ` | Uzbekistan                         |
| `CM` | Cameroon                          | `IT` | Italy                                      | `OM` | Oman                                       | `VA` | Holy See (Vatican City State)      |
| `CN` | China                             | `JE` | Jersey                                     | `PA` | Panama                                     | `VC` | Saint Vincent & The Grenadines     |
| `CO` | Colombia                          | `JM` | Jamaica                                    | `PE` | Peru                                       | `VE` | Venezuela, Bolivarian Republic Of  |
| `CR` | Costa Rica                        | `JO` | Jordan                                     | `PF` | French Polynesia                           | `VG` | Virgin Islands (British)           |
| `CU` | Cuba                              | `JP` | Japan                                      | `PG` | Papua New Guinea                           | `VI` | Virgin Islands (U.S.)              |
| `CV` | Cape Verde                        | `KE` | Kenya                                      | `PH` | Philippines                                | `VN` | Viet Nam                           |
| `CX` | Christmas Island                  | `KG` | Kyrgyzstan                                 | `PK` | Pakistan                                   | `VU` | Vanuatu                            |
| `CY` | Cyprus                            | `KH` | Cambodia                                   | `PL` | Poland                                     | `WF` | Wallis & Futuna Islands            |
| `CZ` | Czech Republic                    | `KI` | Kiribati                                   | `PM` | St. Pierre & Miquelon                      | `WS` | Samoa                              |
| `DE` | Germany                           | `KM` | Comoros                                    | `PN` | Pitcairn                                   | `YE` | Yemen                              |
| `DJ` | Djibouti                          | `KN` | Saint Kitts & Nevis                        | `PR` | Puerto Rico                                | `YT` | Mayotte                            |
| `DK` | Denmark                           | `KP` | Korea, Democratic People’S Republic Of     | `PS` | Palestinian Territory                      | `ZA` | South Africa                       |
| `DM` | Dominica                          | `KR` | Korea, Republic Of                         | `PT` | Portugal                                   | `ZM` | Zambia                             |
| `DO` | Dominican Republic                | `KW` | Kuwait                                     | `PW` | Palau                                      | `ZW` | Zimbabwe                           |
| `DZ` | Algeria                           | `KY` | Cayman Islands                             | `PY` | Paraguay                                   | `ZZ` | Local Country                      |
| `EC` | Ecuador                           | `KZ` | Kazakhstan                                 | `QA` | Qatar                                      |    |                                    |
| `EE` | Estonia                           | `LA` | Lao People’S Democratic Republic           | `RE` | Reunion                                    |    |                                    |

</details>

`whois 139.162.133.252`
```
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See https://apps.db.ripe.net/docs/HTML-Terms-And-Conditions

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '139.162.0.0 - 139.162.255.255'

% Abuse contact for '139.162.0.0 - 139.162.255.255' is 'abuse@linode.com'

inetnum:        139.162.0.0 - 139.162.255.255
netname:        EU-LINODE-20141229
descr:          139.162.0.0/16
org:            ORG-LL72-RIPE
country:        US
admin-c:        TA2589-RIPE
abuse-c:        LAS85-RIPE
tech-c:         TA2589-RIPE
status:         LEGACY
remarks:        Please send abuse reports to abuse@linode.com
mnt-by:         linode-mnt
created:        2004-02-02T16:20:09Z
last-modified:  2022-12-12T21:26:29Z
source:         RIPE
```
Is Network CC `US` but the associated AS, `AS63949` would have (interestingly enough) `NL` 
(which makes little sense, but this what `ipwhois` detects)

### ISP Network Name: `network_name`
List of Python regexes of provider specified network names in WHOIS. 

Names might be `EU-LINODE-20141229`, `DE-D2VODAFONE-20220628`, `DTAG-DIAL16` or `AMAZON-IAD`, `MSFT`

These are not necessarily unique.

Each line needs to be a valid Lua Regular expression that need to match the entire name like 
`EU-LINODE-20141229` or `.*LINODE.*` for `EU-LINODE-20141229`

### Reverse Hostnames: `reverse_hostname`
List of Python regexes of reverse hostnames resolvable via the local DNS resolver.

E.g.
```
$ nslookup 52.23.158.188
188.158.23.52.in-addr.arpa	name = ec2-52-23-158-188.compute-1.amazonaws.com.
```
Empty (NXDOMAIN) results will be matched as `<>`
```
$ nslookup 52.97.246.245
** server can't find 245.246.97.52.in-addr.arpa: NXDOMAIN
```
Each line needs to be a valid Python Regular expression that need to match the entire reverse name 
(without trailing dots), e.g. `.*\.compute-1\.amazonaws\.com` for 
`ec2-52-23-158-188.compute-1.amazonaws.com`

### WHOIS Related Entities: `entities`
List of related WHOIS entities like administrators or organizations.

E.g. Related with `176.112.169.192` (ASN 7764) are `EY1327-RIPE` (VK admin-c), 
`ORG-LLCn4-RIPE` (VK LLC), `RIPE-NCC-END-MNT` (RIPE Contact), `VKCOMPANY-MNT` 
(Maintainer for VK objects), `VKNC` (VK admin-c), `MAIL-RU` (abuse-c)

### IP CIDR Networks: `ip_networks`
List of IPv4 or IPv6 CIDR networks to block access from. E.g. `176.112.168.0/21`

There is no check for set host-bits, the mask is just applied to both addresses to compare 
network addresses, if they match the request is blocked. This means for example 
`176.112.170.0/21` is equivalent to `176.112.168.0/21`

### Geonames IDs (MaxMind): `geo_location_ids`
A list of numeric [Geoname IDs](https://www.geonames.org/). Matched against the City's, 
Most specific Subdivision's, Country's Geoname ID.

E.g.
```
# Virgina, USA
6254928

# Ashburn, Virgina, USA
4744870
```

# Logs
The script additionally generates log lines like this for later examination
```
Mai 01 04:06:34 honeypot mail-audit[1084587]: user=<honey-craig>, service=imap, ip=176.112.169.218, host=rimap26.i.mail.ru, asn=AS47764, as_cc=RU, as_desc=<VK-AS, RU>, as_org=<LLC VK>, net_name=<VK-FRONT>, net_cc=RU, entity=EY1327-RIPE, entity=ORG-LLCn4-RIPE, entity=RIPE-NCC-END-MNT, entity=VKCOMPANY-MNT, entity=VKNC, entity=MAIL-RU, city=<550478/Khasavyurt>, subdivision=<567293/Dagestan>, country=<2017370/Russia>, represented_country=<None/None>, registered_country=<2017370/Russia>, lat=43.2465, lon=46.59, rad=20km
Mai 03 13:07:45 honeypot mail-audit[1084587]: user=<honey>, service=imap, ip=172.17.1.204, host=dhcp204.internal, asn=None, as_cc=ZZ, as_desc=<MPI PKS local network>, as_org=<None>, net_name=<DHCP Network>, net_cc=ZZ, entity=
Mai 06 04:20:25 honeypot mail-audit[1084587]: user=<honey-sugar>, service=imap, ip=139.162.133.252, host=node-eu-0001.email2-cloud.com, asn=AS63949, as_cc=NL, as_desc=<AKAMAI-LINODE-AP Akamai Connected Cloud, SG>, as_org=<Akamai Connected Cloud>, net_name=<EU-LINODE-20141229>, net_cc=US, entity=linode-mnt, entity=ORG-LL72-RIPE, entity=TA2589-RIPE, entity=LAS85-RIPE, city=<2925533/Frankfurt am Main>, subdivision=<2905330/Hesse>, country=<2921044/Germany>, represented_country=<None/None>, registered_country=<2750405/The Netherlands>, lat=50.1188, lon=8.6843, rad=20km
Mai 06 11:00:20 honeypot mail-audit[1084587]: user=<honey-gmail-pop>, service=pop3, ip=209.85.218.15, host=mail-ej1-f15.google.com, asn=AS15169, as_cc=US, as_desc=<GOOGLE, US>, as_org=<GOOGLE>, net_name=<GOOGLE>, net_cc=None, entity=GOGL, city=<None/None>, country=<6252001/United States>, represented_country=<None/None>, registered_country=<6252001/United States>, lat=37.751, lon=-97.822, rad=1000km
Mai 06 11:05:24 honeypot mail-audit[1084587]: user=<honey-gmail-smtp>, service=smtp, ip=209.85.218.53, host=mail-ej1-f53.google.com, asn=AS15169, as_cc=US, as_desc=<GOOGLE, US>, as_org=<GOOGLE>, net_name=<GOOGLE>, net_cc=None, entity=GOGL, city=<None/None>, country=<6252001/United States>, represented_country=<None/None>, registered_country=<6252001/United States>, lat=37.751, lon=-97.822, rad=1000km
```
The information is also deconstructed into journal meta information.

<details>

```json
{
  "AUDIT_AS_DESC":"GOOGLE, US",
  "_RUNTIME_SCOPE":"system",
  "AUDIT_MAXMIND_COUNTRY":"{'name': 'United States', 'geoname_id': 6252001, 'code': 'US'}",
  "_BOOT_ID":"...",
  "AUDIT_NET_NAME":"GOOGLE",
  "AUDIT_IP":"209.85.218.53",
  "AUDIT_MATCHED":"None",
  "_EXE":"/usr/bin/python3.12",
  "_MACHINE_ID":"...",
  "AUDIT_MAXMIND_CITY":"{'name': None, 'geoname_id': None, 'code': None}",
  "AUDIT_MAXMIND_REGISTERED_COUNTRY":"{'name': 'United States', 'geoname_id': 6252001, 'code': 'US'}",
  "_CMDLINE":"...",
  "CODE_LINE":"129",
  "_AUDIT_LOGINUID":"1000",
  "AUDIT_RESERVED":"False",
  "_CAP_EFFECTIVE":"0",
  "AUDIT_SERVICE":"smtp",
  "AUDIT_NET_CC":"None",
  "_SYSTEMD_CGROUP":"...",
  "__CURSOR":"...",
  "_SYSTEMD_INVOCATION_ID":"...",
  "_AUDIT_SESSION":"4",
  "_PID":"4161694",
  "_HOSTNAME":"...",
  "__REALTIME_TIMESTAMP":"1727355927030069",
  "AUDIT_MAXMIND_POSTAL_CODE":"None",
  "__SEQNUM_ID":"...",
  "AUDIT_BLOCKED":"False",
  "_SOURCE_REALTIME_TIMESTAMP":"1727355927030042",
  "AUDIT_MAXMIND_REPRESENTED_COUNTRY":"{'name': None, 'geoname_id': None, 'code': None}",
  "AUDIT_MAXMIND_LOCATION":"{'accuracy_radius': 1000, 'latitude': 37.751, 'longitude': -97.822, 'time_zone': 'America/Chicago'}",
  "_SYSTEMD_UNIT":"user@1000.service",
  "_SYSTEMD_USER_UNIT":"...",
  "SYSLOG_IDENTIFIER":"mail-audit",
  "_SYSTEMD_SLICE":"user-1000.slice",
  "_COMM":"python",
  "_SYSTEMD_USER_SLICE":"app.slice",
  "AUDIT_ENTITIES":"['GOGL']",
  "AUDIT_USER":"bbecker",
  "_SYSTEMD_OWNER_UID":"1000",
  "_UID":"1000",
  "CODE_FUNC":"audit_log",
  "__SEQNUM":"4339035",
  "AUDIT_ASN":"AS15169",
  "AUDIT_LOG":"True",
  "__MONOTONIC_TIMESTAMP":"872567118506",
  "_TRANSPORT":"journal",
  "AUDIT_MAXMIND_SUBDIVISIONS":"()",
  "AUDIT_REV_HOST":"mail-ej1-f53.google.com",
  "AUDIT_MAXMIND_CONTINENT":"{'name': 'North America', 'geoname_id': 6255149, 'code': 'NA'}",
  "_GID":"1000",
  "MESSAGE":"user=<bbecker>, service=smtp, ip=209.85.218.53, host=mail-ej1-f53.google.com, asn=AS15169, as_cc=US, as_desc=<GOOGLE, US>, as_org=<GOOGLE>, net_name=<details>, net_cc=None, entity=GOGL, city=<None/None>, country=<6252001/United States>, represented_country=<None/None>, registered_country=<6252001/United States>, lat=37.751, lon=-97.822, rad=1000km",
  "CODE_FILE":"/path/to/dovecot_web_auth/audit.py",
  "AUDIT_AS_CC":"US"
}
```

</details>

A script to retrieve user statistics of the last 24h might look something like this
```bash
journalctl -S "24 hours ago" -g "mail-audit" | awk -F : '{print $4}' | sort | uniq -c | sort -h
```

More sophisticated analytics can be generated with `audit_mail.py`, which need a yaml file describing
additional information about ASN that should be considered, meant for generating an email.