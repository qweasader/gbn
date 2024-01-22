# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:sonicwall_scrutinizer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103533");
  script_cve_id("CVE-2012-3951");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2024-01-17T06:33:34+0000");

  script_name("Plixer Scrutinizer Default Credentials (MySQL Protocol)");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210213215151/https://www.securityfocus.com/bid/54731/");

  script_tag(name:"last_modification", value:"2024-01-17 06:33:34 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"creation_date", value:"2012-08-08 12:18:06 +0200 (Wed, 08 Aug 2012)");
  script_category(ACT_ATTACK);
  script_family("Databases");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("mysql_version.nasl", "gb_scrutinizer_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80, "Services/mysql", 3306);
  script_mandatory_keys("scrutinizer/installed");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Plixer Scrutinizer is using known default credentials in the
  MySQL component.");

  script_tag(name:"vuldetect", value:"Tries to login via MySQL using known default credentials.");

  script_tag(name:"impact", value:"Successful attacks can allow an attacker to gain access to the
  affected application using the default authentication credentials scrutremote:admin.");

  script_tag(name:"affected", value:"Plixer Scrutinizer 9.5.0 is known to be vulnerable. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("host_details.inc");
include("byte_func.inc");
include("port_service_func.inc");

if(!get_app_location(cpe:CPE, nofork:TRUE))
  exit(0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

port = service_get_port(default:3306, proto:"mysql");

if(get_kb_item("MySQL/" + port + "/blocked"))
  exit(0);

sock = open_sock_tcp(port);
if(!sock)
  exit(0);

res =  recv(socket:sock, length:4);
if(!res)
  exit(0);

plen = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);
res =  recv(socket:sock, length:plen);

for (i = 0; i < strlen(res); i++) {
  if (ord(res[i]) != 0) {
    ver += res[i];
  }
  else {
    break;
  }
}

p = strlen(ver);
if(p < 5)
  exit(0);

salt = substr(res, 5 + p, 12 + p) + substr(res, 32 + p, 43 + p);

username = "scrutremote";
password = "admin";

sha_pass1 = SHA1(password);
sha_pass2 = SHA1(sha_pass1);
sha_pass3 = SHA1(salt + sha_pass2);

l = strlen(sha_pass3);

for (i = 0; i < l; i++) {
  pass += raw_string(ord(sha_pass1[i]) ^ ord(sha_pass3[i]));
}


req = raw_string(0x05,0xa6,0x0f,0x00,0x00,0x00,0x00,0x01,0x21,0x00,0x00,0x00,0x00,0x00,
                 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                 0x00,0x00,0x00,0x00);

req += raw_string(username, 0x00, 0x14, pass);

len = strlen(req);
req = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, 0x01) + req;

send(socket:sock,data:req);
res = recv(socket:sock, length:4);

if(!res || strlen(res) < 4) {
  close(sock);
  exit(0);
}

plen = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);

res = recv(socket:sock, length:plen);
if(!res || strlen(res) < plen)
  exit(0);

errno = ord(res[2]) << 8 | ord(res[1]);

if(errno > 0 || errno == "")
  exit(0);

cmd = "show databases";
len = strlen(cmd) + 1;

req = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, 0x00, 0x03, cmd);

send(socket:sock, data:req);

z = 0;
while(TRUE) {

  z++;
  if(z > 15)
    exit(0);

  res =  recv(socket:sock, length:4);

  if(!res || strlen(res) < 4) {
    close(sock);
    exit(0);
  }

  plen = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);

  res = recv(socket:sock, length:plen);
  if(!res || strlen(res) < plen)
    break;

  if("plixer" >< res || "information_schema" >< res) {
    close(sock);
    security_message(port:port);
    exit(0);
  }
}

close(sock);
