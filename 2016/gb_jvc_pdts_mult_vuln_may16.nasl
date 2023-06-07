###############################################################################
# OpenVAS Vulnerability Test
#
# JVC Multiple Products Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808200");
  script_version("2021-10-15T11:13:32+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-15 11:13:32 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-05-20 14:37:04 +0530 (Fri, 20 May 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("JVC Multiple Products Multiple Vulnerabilities");

  script_tag(name:"summary", value:"JVC product(s) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Insufficient validation of user supplied input via parameters
    'video.input.COMMENT', 'video.input.STATUS' and 'interface(01).dhcp.status'
    to '/api/param?'.

  - Multiple cross-site request forgery vulnerabilities.

  - By default everything is trasmite over HTTP, including credentials.

  - Possible to login with default credential admin:jvc or admin:[model-of-camera].");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser, to bypass
  authentication and to obtain sensitive information.");

  script_tag(name:"affected", value:"JVC HDR VR-809/816
  Network cameras VN-C*, VN-V*, VN-X* with firmwares 1.03 and 2.03");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137034/OLSA-2016-04-01.txt");
  script_xref(name:"URL", value:"http://www.orwelllabs.com/2016/04/jvc-multiple-products-multiple.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("JVC_API/banner", "Basic_realm/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);

if(banner =~ "Server: JVC.*API Server" && 'WWW-Authenticate: Basic realm' >< banner) {

  auth = base64(str:'admin:jvc');

  url = "/";
  buf = http_get_cache(item:url, port:port);
  if(buf !~ "^HTTP/1\.[01] 401")
    exit(0);

  req = http_get(item:url, port:port);
  req = ereg_replace(string:req, pattern:'\r\n\r\n', replace: '\r\nAuthorization: Basic ' + auth + '\r\n\r\n');
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(buf =~ "^HTTP/1\.[01] 200" && buf =~ "Server: JVC.*API Server") {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

exit(0);
