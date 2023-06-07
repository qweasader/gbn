###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Rational ClearQuest Multiple Information Disclosure Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803709");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2012-0744");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-06-03 17:40:28 +0530 (Mon, 03 Jun 2013)");
  script_name("IBM Rational ClearQuest Multiple Information Disclosure Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74671");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54222");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21606317");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21599361");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain potentially
  sensitive information.");
  script_tag(name:"affected", value:"IBM Rational ClearQuest 7.1.x to 7.1.2.7 and 8.x to 8.0.0.3");
  script_tag(name:"insight", value:"The flaws are due to improper access controls on certain post-installation
  sample scripts. By sending a direct request, an attacker could obtain system
  paths, product versions, and other sensitive information.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"IBM Rational ClearQuest is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

sndReq = http_get(item:"/cqweb/login", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

if(">Rational<" >< rcvRes && "Welcome to Rational ClearQuest Web" >< rcvRes)
{

  sndReq = http_get(item:"/cqweb/j_security_check", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if((rcvRes =~ "HTTP/1.. 200 OK") && (rcvRes !~ "HTTP/1.. 404")
     && (">Object not found!<" >!< rcvRes))
  {
    security_message(port);
    exit(0);
  }
}
