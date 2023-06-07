###############################################################################
# OpenVAS Vulnerability Test
#
# OmniPro HTTPd 2.08 scripts source full disclosure
#
# Authors:
# Gregory Duchemin <plugin@intranode.com>
#
# Copyright:
# Copyright (C) 2001 INTRANODE
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
  script_oid("1.3.6.1.4.1.25623.1.0.10716");
  script_version("2022-05-12T09:32:01+0000");
  script_cve_id("CVE-2001-0778");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2788");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("OmniPro HTTPd 2.08 scripts source full disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 INTRANODE");
  script_family("Web application abuses");
  script_dependencies("gb_omnihttpd_detect.nasl");
  script_mandatory_keys("omnihttpd/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"OmniPro HTTPd 2.08 suffers from a security vulnerability that permits
  malicious users to get the full source code of scripting files.");

  script_tag(name:"insight", value:"By appending an ASCII/Unicode space char '%20' at the script suffix,
  the web server will no longer interpret it and rather send it back clearly
  as a simple document to the user in the same manner as it usually does to
  process HTML-like files.

  The flaw does not work with files located in CGI directories (e.g cgibin,
  cgi-win)

  Exploit: GET /test.php%20 HTTP/1.0");

  script_tag(name:"affected", value:"Up to release 2.08");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

CPE = "cpe:/a:omnicron:omnihttpd";

include("host_details.inc");
include("http_func.inc");

function check(poison, port)
{
  soc = http_open_socket(port);
  if(!soc) return(0);

  request = http_get(item:poison, port:port);
  send(socket:soc, data:request);
  response = http_recv(socket:soc);
  http_close_socket(soc);

  regex_signature[2] = "<?";
  if (regex_signature[2] >< response)
    return(1);
  else
    return(0);
}

if(!port = get_app_port(cpe:CPE))
  exit(0);

Egg = "%20 ";
signature = "test.php";

poison = string("/", signature, Egg);

if(check(poison:poison, port:port)){
  security_message(port:port);
  exit(0);
}

exit( 99 );
