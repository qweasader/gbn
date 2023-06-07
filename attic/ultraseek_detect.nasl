# OpenVAS Vulnerability Test
# Description: Ultraseek Web Server Detect
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus <noamr@securiteam.com> & SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10791");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0996", "CVE-2000-1019");
  script_name("Ultraseek Web Server Detect");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Noam Rathaus <noamr@securiteam.com> & SecuriTeam");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Ultraseek/banner");
  script_require_ports("Services/www", 8765);

  script_xref(name:"URL", value:"http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeamwords=Ultraseek");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/874");

  script_tag(name:"solution", value:"Make sure you are running the latest version of the Ultraseek
  Web Server or disable it if you do not use it.");

  script_tag(name:"summary", value:"Ultraseek Web Server is running on this host.
  Ultraseek has been known to contain security vulnerabilities ranging from
  Buffer Overflows to Cross Site Scripting issues.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # TODO: The VT has an initial "useless message. ultraseek_dos.nasl already do this check" message but which doesn't exist in the feed. For now we're keeping it deprecated.

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:8765);
banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

if("Server: Ultraseek" >< banner) {
  security_message(port:port);
  exit(0);
}

exit(99);
