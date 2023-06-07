# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142111");
  script_version("2021-08-27T12:01:24+0000");
  script_tag(name:"last_modification", value:"2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-03-08 16:17:19 +0700 (Fri, 08 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-05 15:38:00 +0000 (Tue, 05 Feb 2019)");

  script_cve_id("CVE-2018-14708", "CVE-2018-14709");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Drobo NAS Multiple Vulnerabilities in NASd");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drobo_nas_consolidation.nasl");
  script_mandatory_keys("drobo/nasd/detected", "drobo/nas/esaid");

  script_tag(name:"summary", value:"Drobo NAS are prone to multiple vulnerabilities in NASd.");

  script_tag(name:"insight", value:"Drobo NAS are prone to multiple vulnerabilities in NASd:

  - Missing Transport Security in Client-Server Communications Between Drobo Dashboard and NASd (CVE-2018-14708)

  - Insufficient Authentication in Client-Server Communications Between Drobo Dashboard and NASd (CVE-2018-14709)");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"vuldetect", value:"Sends a crafted request and checks the response.");

  script_xref(name:"URL", value:"https://blog.securityevaluators.com/call-me-a-doctor-new-vulnerabilities-in-drobo5n2-4f1d885df7fc");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");

port = 5001;

if (! get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

if (!esaid = get_kb_item("drobo/nas/esaid"))
  exit(0);

login_preamble = raw_string(0x44, 0x52, 0x49, 0x4e, 0x45, 0x54, 0x54, 0x4d,
                            0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc,
                            esaid,
                            0x00, 0x00, 0x00, 0x00, 0x00,
                            esaid,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00);

cmd16_preamble = raw_string(0x44, 0x52, 0x49, 0x4e, 0x45, 0x54, 0x54, 0x4d,
                            0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76);

cmd16_xml = raw_string(0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65,
                       0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31,
                       0x2e, 0x30, 0x22, 0x20, 0x65, 0x6e, 0x63, 0x6f,
                       0x64, 0x69, 0x6e, 0x67, 0x3d, 0x22, 0x55, 0x54,
                       0x46, 0x2d, 0x38, 0x22, 0x20, 0x73, 0x74, 0x61,
                       0x6e, 0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x3d,
                       0x22, 0x79, 0x65, 0x73, 0x22, 0x3f, 0x3e, 0x3c,
                       0x54, 0x4d, 0x43, 0x6d, 0x64, 0x3e, 0x3c, 0x43,
                       0x6d, 0x64, 0x49, 0x44, 0x3e, 0x36, 0x31, 0x3c,
                       0x2f, 0x43, 0x6d, 0x64, 0x49, 0x44, 0x3e, 0x3c,
                       0x45, 0x53, 0x41, 0x49, 0x44, 0x3e,
                       esaid,
                       0x3c, 0x2f, 0x45, 0x53, 0x41, 0x49, 0x44, 0x3e, 0x3c,
                       0x2f, 0x54, 0x4d, 0x43, 0x6d, 0x64, 0x3e, 0x00);

send(socket: soc, data: login_preamble);
send(socket: soc, data: cmd16_preamble);
send(socket: soc, data: cmd16_xml);

recv = recv(socket: soc, length: 4096);

close(soc);

res = bin2string(ddata: recv, noprint_replacement: "");

if ("Temperature" >< res && "UpTime" >< res) {
  report = 'It was possible to obtain some system information from the device.\n\nResult:\n\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
