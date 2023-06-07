###############################################################################
# OpenVAS Vulnerability Test
#
# BoltWire Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803961");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-2651");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-11-07 16:32:49 +0530 (Thu, 07 Nov 2013)");
  script_name("BoltWire Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials.");

  script_tag(name:"affected", value:"BoltWire version 3.5 and earlier");

  script_tag(name:"insight", value:"An error exists in the index.php script which fails to properly sanitize
user-supplied input to 'p' and 'content' parameter before using.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether
it is able to read the string or not.");

  script_tag(name:"summary", value:"BoltWire is prone to multiple cross-site scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62907");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/87809");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123558");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2013-10/0033.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir( make_list_unique( "/", "/bolt", "/boltwire", "/field", "/bolt/field", "/boltwire/field", http_cgi_dirs( port:port ) ) ) {

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if(res && "<title>BoltWire: Main</title>" >< res && "Radical Results!" >< res) {
    url = url + '?p=%253Cscript%253Ealert(%2527XSS-TEST%2527)%253B%253C%252Fscript%253E';
    match = "<script>alert\('XSS-TEST'\);</script>";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:match))
    {
      report = http_report_vuln_url( port:port, url:url );
      security_message(port:port, data:url);
      exit(0);
    }
  }
}
