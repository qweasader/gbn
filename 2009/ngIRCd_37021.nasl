###############################################################################
# OpenVAS Vulnerability Test
#
# ngIRCd SSL/TLS Support MOTD Request Multiple Denial Of Service Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100347");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-11-16 11:47:06 +0100 (Mon, 16 Nov 2009)");
  script_cve_id("CVE-2009-4652");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_name("ngIRCd SSL/TLS Support MOTD Request Multiple Denial Of Service Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37021");
  script_xref(name:"URL", value:"http://arthur.barton.de/cgi-bin/gitweb.cgi?p=ngircd.git;a=commit;h=627b0b713c52406e50c84bb9459e7794262920a2");
  script_xref(name:"URL", value:"http://ngircd.barton.de/doc/ChangeLog");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ircd.nasl");
  script_require_ports("Services/irc", 6667);
  script_mandatory_keys("ircd/banner");

  script_tag(name:"solution", value:"These issues have been fixed in ngIRCd 14.1. Please see the references for details.");

  script_tag(name:"summary", value:"ngIRCd is prone to multiple denial-of-service vulnerabilities when the
  server is running with SSL/TLS support.");

  script_tag(name:"impact", value:"Attackers can leverage these issues to crash the server and deny
  access to legitimate users.");

  script_tag(name:"affected", value:"ngIRCd 13 through ngIRCd 14 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:6667, proto:"irc");
banner = get_kb_item(string("irc/banner/", port));
if(!banner || "ngircd" >!< banner)
  exit(0);

version = eregmatch(pattern:"ngircd-([0-9.]+[~rc0-9]*)\.+", string: banner);

if(!isnull(version[1])) {

  if("~" >< version[1]) {
    vers = str_replace(string:version[1], find:string("~"),replace:".");
  } else {
    vers = version[1];
  }

  if(vers =~ "^13\." || vers =~ "^14\.rc") {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
