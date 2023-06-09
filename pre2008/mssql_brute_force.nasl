###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft's SQL Server Brute Force
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2005 H D Moore
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

#             MSSQL Brute Forcer
#
# This script checks a MSSQL Server instance for common
# username and password combinations. If you know of a
# common/default account that is not listed, please
# submit it to:
#
# https://forum.greenbone.net/c/vulnerability-tests/7
#
# System accounts with blank passwords are checked for in
# a separate plugin (mssql_blank_password.nasl). This plugin
# is geared towards accounts created by rushed admins or
# certain software installations.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10862");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft's SQL Server Brute Force");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 H D Moore");
  script_family("Brute force attacks");
  script_dependencies("mssqlserver_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/mssql", 1433);
  script_mandatory_keys("microsoft/sqlserver/detected");
  script_exclude_keys("default_credentials/disable_brute_force_checks");

  script_tag(name:"solution", value:"Please set a difficult to guess password for these accounts.");

  script_tag(name:"summary", value:"The MSSQL Server has a common password for one or more accounts.
  These accounts may be used to gain access to the records in the database or even allow
  remote command execution.");

  script_tag(name:"impact", value:"An attacker can use these accounts to read and/or
  modify data on your MSSQL server. In addition, the attacker may be able to launch programs on the
  target Operating system");

  script_tag(name:"insight", value:"If you want to use additional passwords for the 'sa' and 'admin' accounts
  you need to disable safe_checks().");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("port_service_func.inc");

if(get_kb_item("default_credentials/disable_brute_force_checks"))
  exit(0);

pkt_hdr = raw_string(
    0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);


pkt_pt2 = raw_string (
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x61, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x18, 0x81, 0xb8, 0x2c, 0x08, 0x03,
    0x01, 0x06, 0x0a, 0x09, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x73, 0x71, 0x75, 0x65, 0x6c, 0x64, 0x61,
    0x20, 0x31, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
);

pkt_pt3 = raw_string (
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x4d, 0x53, 0x44,
    0x42, 0x4c, 0x49, 0x42, 0x00, 0x00, 0x00, 0x07, 0x06, 0x00, 0x00,
    0x00, 0x00, 0x0d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);

pkt_lang = raw_string(
    0x02, 0x01, 0x00, 0x47, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00
);


function sql_recv(socket)
{
 local_var head, len_hi, len_lo, len, body;

 head = recv(socket:socket, length:4, min:4);
 if(strlen(head) < 4) return NULL;

 len_hi = 256 * ord(head[2]);
 len_lo = ord(head[3]);

 len = len_hi + len_lo;
 body = recv(socket:socket, length:len);
 return(string(head, body));
}

function make_sql_login_pkt (username, password)
{
    local_var ulen, plen, upad, ppad, ubuf, pbuf, nul, ublen, pblen, sql_packet;

    ulen = strlen(username);
    plen = strlen(password);

    upad = 30 - ulen;
    ppad = 30 - plen;

    ubuf = "";
    pbuf = "";

    nul = raw_string(0x00);


    if(ulen)
    {
        ublen = raw_string(ulen % 255);
    } else {
        ublen = raw_string(0x00);
    }


    if(plen)
    {
        pblen =  raw_string(plen % 255);
    } else {
        pblen = raw_string(0x00);
    }

    ubuf = string(username, crap(data:nul, length:upad));
    pbuf = string(password, crap(data:nul, length:ppad));

    sql_packet = string(pkt_hdr,ubuf,ublen,pbuf,pblen,pkt_pt2,pblen,pbuf,pkt_pt3);

    return sql_packet;
}

# Additional account / password pairs taken from:
# https://github.com/mubix/post-exploitation-wiki

user[0]="sa";       pass[0]="sa";

user[1]="probe";    pass[1]="probe";
user[2]="probe";    pass[2]="password";

user[3]="sql";      pass[3]="sql";

user[4]="ELNAdmin"; pass[4]="ELNAdmin";
user[5]="msi";      pass[5]="keyboa5";

# Avoid "sa" and "admin" account lockout with too many failed logins
if( ! safe_checks() ) {
  user[6]="admin";  pass[6]="administrator";
  user[7]="admin";  pass[7]="password";
  user[8]="admin";  pass[8]="admin";
  user[9]="sa";     pass[9]="password";
  user[10]="sa";    pass[10]="administrator";
  user[11]="sa";    pass[11]="admin";
  user[12]="sa";    pass[12]="sql";
  user[13]="sa";    pass[13]="SQL";
  user[14]="sa";    pass[14]="SLXMaster";
  user[15]="sa";    pass[15]="SLXMa$t3r";
  user[16]="sa";    pass[16]="sage";
  user[17]="sa";    pass[17]="CambridgeSoft_SA";
  user[18]="sa";    pass[18]="mypassword";
  user[19]="sa";    pass[19]="PCAmerica";
  user[20]="sa";    pass[20]="pcAmer1ca";
  user[21]="sa";    pass[21]="ActbySage1!";
  user[22]="sa";    pass[22]="Hpdsdb000001";
  user[23]="sa";    pass[23]="hpdss";
  user[24]="sa";    pass[24]="t9AranuHA7";
  user[25]="sa";    pass[25]="Cod3p@l";
  user[26]="sa";    pass[26]="111";
  user[27]="sa";    pass[27]="DHLadmin@1";
}

report = "";
port = service_get_port( default:1433, proto:"mssql" );


found = 0;

if(get_port_state(port)) {

  for(i=0;user[i];i=i+1) {

    soc = open_sock_tcp(port);
    if(!soc) exit(0);

    username = user[i];
    password = pass[i];

    # this creates a variable called sql_packet
    sql_packet = make_sql_login_pkt(username:username, password:password);

    send(socket:soc, data:sql_packet);
    send(socket:soc, data:pkt_lang);

    r  = sql_recv(socket:soc);
    close(soc);

    if(strlen(r) > 10 && ord(r[8]) == 0xE3) {
      report = report + "Account '" + username + "' has password '" + password + "'\n";
      found = 1;
    }
  }
}

if(found) {
  report = "The following accounts were found on the MSSQL Server:\n" + report;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
