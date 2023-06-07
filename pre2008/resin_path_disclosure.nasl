###############################################################################
# OpenVAS Vulnerability Test
#
# Resin DOS device path disclosure
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11048");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-2090");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5252");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Resin DOS device path disclosure");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("gb_caucho_resin_detect.nasl");
  script_mandatory_keys("caucho/resin/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Upgrade to a later software version.");

  script_tag(name:"summary", value:"Resin will reveal the physical path of the webroot
  when asked for a special DOS device, e.g. lpt9.xtp");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain further knowledge
  about the remote filesystem layout.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:caucho:resin";

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port))
  exit(0);

version = infos["version"];
location = infos["location"];

# Requesting a DOS device may hang some servers
# According to Peter Gründl's advisory:
# Vulnerable:
# Resin 2.1.1 on Windows 2000 Server
# Resin 2.1.2 on Windows 2000 Server
# <security-protocols@hushmail.com> added Resin 2.1.0
# Not Vulnerable:
# Resin 2.1.s020711 on Windows 2000 Server
#
# The banner for snapshot 020604 looks like this:
# Server: Resin/2.1.s020604

# I suppose that any 2.1 snapshot is all right.
if (egrep(pattern:"2\.((0\..*)|(1\.[0-2]))", string:version, icase:1)) vulnver=1;

if (safe_checks())
{
 if (vulnver)
 {
  msg = string("*** The scanner solely relied on the version number of your\n",
  "*** server, so this may be a false alert.\n");
  security_message(port: port, data: msg);
 }
 exit(0);
}

req = http_get(item:"/aux.xtp", port:port);

soc = open_sock_tcp(port);
if (!soc) exit(0);
send(socket:soc, data:req);
h = http_recv_headers2(socket:soc);
r = http_recv_body(socket:soc, headers:h);
close(soc);

badreq=0; vuln=0;
if (egrep(pattern: "^500 ", string: h)) badreq=1;

if (egrep(pattern: "[CDE]:\\(.*\\)*aux.xtp", string:r)) vuln=1;

if (vuln) {
  path = egrep(pattern: "[CDE]:\\(.*\\)*aux.xtp", string:r);
  path = ereg_replace(pattern:".*([CDE]:\\.*aux\.xtp).*", string:path, replace:"\1");

msg = "The remote web server reveals the physical path of the
webroot when asked for a special DOS device, e.g. lpt9.xtp

For instance, requesting :

GET /aux.xtp

Returns the following path(s) :

" + path + "

An attacker may use this flaw to gain further knowledge
about the remote filesystem layout.

Solution: Upgrade to a later software version.";
  security_message(port:port, data:msg); exit(0);
}

if (vulnver) {
  msg = string("*** The version number of your server looks vulnerable\n",
               "*** but the attack did not succeed, so this may be a false alert.\n");
  security_message(port: port, data: msg);
}

exit(0);
