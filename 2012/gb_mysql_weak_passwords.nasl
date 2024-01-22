# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103551");
  script_version("2023-11-02T05:05:26+0000");
  script_cve_id("CVE-2001-0645", "CVE-2004-2357", "CVE-2006-1451", "CVE-2007-2554",
                "CVE-2007-6081", "CVE-2009-0919", "CVE-2014-3419", "CVE-2015-4669",
                "CVE-2016-6531", "CVE-2018-15719");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2012-08-23 10:38:09 +0200 (Thu, 23 Aug 2012)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)");
  script_name("MySQL / MariaDB Default Credentials (MySQL Protocol)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("mysql_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL_MariaDB/installed");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"It was possible to login into the remote MySQL as
  root using weak credentials.");

  script_tag(name:"affected", value:"The following products are know to use such weak credentials:

  - CVE-2001-0645: Symantec/AXENT NetProwler 3.5.x

  - CVE-2004-2357: Proofpoint Protection Server

  - CVE-2006-1451: MySQL Manager in Apple Mac OS X 10.3.9 and 10.4.6

  - CVE-2007-2554: Associated Press (AP) Newspower 4.0.1 and earlier

  - CVE-2007-6081: AdventNet EventLog Analyzer build 4030

  - CVE-2009-0919: XAMPP

  - CVE-2014-3419: Infoblox NetMRI before 6.8.5

  - CVE-2015-4669: Xsuite 2.x

  - CVE-2016-6531, CVE-2018-15719: Open Dental before version 18.4

  Other products might be affected as well.");

  script_tag(name:"solution", value:"- Change the password as soon as possible

  - Contact the vendor for other possible fixes / updates");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("byte_func.inc");
include("host_details.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

cpe_list = make_list("cpe:/a:oracle:mysql",
                     "cpe:/a:mariadb:mariadb");

if(!infos = get_app_port_from_list(cpe_list:cpe_list))
  exit(0);

port = infos["port"];
cpe  = infos["cpe"];

if(get_kb_item( "MySQL/" + port + "/blocked"))
  exit(0);

if(!get_app_location( cpe:cpe, port:port, nofork:TRUE))
  exit(0);

username = "root";
passwords = make_list("admin", "root", "mysql", "password", "passw0rd", "123456", "12345678", "mysqladmin", "qwerty", "letmein", "database", "");

foreach password(passwords) {

  ver = "";
  pass = "";
  req = "";
  native = FALSE;

  if(!sock = open_sock_tcp(port))
    exit(0);

  res = recv(socket:sock, length:4);
  if(!res) {
    close(sock);
    exit(0);
  }

  plen = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);
  res = recv(socket:sock, length:plen);

  if("mysql_native_password" >< res)
    native = TRUE;

  for(i = 0; i < strlen(res); i++) {
    if(ord(res[i]) != 0) {
      ver += res[i];
    } else {
      break;
    }
  }

  p = strlen(ver);
  if(p < 5) {
    close(sock);
    exit(0);
  }

  if(!caps = substr(res, 14 + p, 15 + p))
    continue;

  caps = ord(caps[0]) | ord(caps[1]) << 8;
  proto_is_41 = (caps & 512);
  if(!proto_is_41) {
    close(sock);
    exit(0);
  }

  salt = substr(res, 5 + p, 12 + p);

  if(strlen(res) > (44 + p))
    salt += substr(res, 32 + p, 43 + p);

  sha_pass1 = SHA1(password);
  sha_pass2 = SHA1(sha_pass1);
  sha_pass3 = SHA1(salt + sha_pass2);

  l = strlen(sha_pass3);

  for(i = 0; i < l; i++)
    pass += raw_string(ord(sha_pass1[i]) ^ ord(sha_pass3[i]));

  req = raw_string(0x05,0xa6,0x0f,0x00,0x00,0x00,0x00,0x01,0x21,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00);

  req += raw_string(username, 0x00);

  if(strlen(password) > 0)
    req += raw_string(0x14, pass);
  else
    req += raw_string(0x00);

  if(native)
    req += raw_string(0x6d,0x79,0x73,0x71,0x6c,0x5f,0x6e,0x61,0x74,0x69,0x76,0x65,0x5f,0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,0x00);

  len = strlen(req);
  req = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, 0x01) + req;

  send(socket:sock, data:req);
  res = recv(socket:sock, length:4);

  if(!res || strlen(res) < 4) {
    close(sock);
    continue;
  }

  plen = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);

  res =  recv(socket:sock, length:plen);
  if(!res || strlen(res) < plen) {
    close(sock);
    continue;
  }

  errno = ord(res[2]) << 8 | ord(res[1]);

  if(errno > 0 || errno == "") {
    close(sock);
    continue;
  }

  cmd = "show databases";
  len = strlen(cmd) + 1;
  req = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, 0x00, 0x03, cmd);

  send(socket:sock, data:req);

  z = 0;
  while(1) {

    z++;
    if(z > 15)
      exit(0);

    res =  recv(socket:sock, length:4);

    if(!res || strlen(res) < 4) {
      close(sock);
      exit(0);
    }

    plen = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);

    res =  recv(socket:sock, length:plen);
    if(!res || strlen(res) < plen)
      break;

    if("information_schema" >< res) {
      close(sock);

      data = "It was possible to login as root";

      if(strlen(password) > 0)
        data += ' with password "' + password + '".';
      else
        data += ' with an empty password.';

      data += '\n\n';

      security_message(port:port, data:data);
      exit(0);
    }
  }
  close(sock);
}

close(sock);
exit(99);
