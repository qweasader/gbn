###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Sametime Classic Meeting Server Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804825");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-4747", "CVE-2014-4748");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-08-27 17:35:20 +0530 (Wed, 27 Aug 2014)");
  script_name("IBM Sametime Classic Meeting Server Multiple Vulnerabilities");

  script_tag(name:"summary", value:"IBM Sametime Classic Meeting Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to read string or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - improper validation of user supplied input.

  - presence of password hash in HTML source.");

  script_tag(name:"impact", value:"Successful exploitation will allow local attacker to gain access to the meeting
  password hash from the HTML source and allow remote attackers to execute
  arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"IBM Sametime Classic Meeting Server 8.x through 8.5.2.1.");

  script_tag(name:"solution", value:"Upgrade or apply patches as given in the referenced links.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127830");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68823");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68841");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127831");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21679221");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21679454");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

http_port = http_get_port(default:80);

url = "/stcenter.nsf";

sndReq = http_get(item: url,  port:http_port);
rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

if (rcvRes && ">Welcome to IBM Lotus Sametime<" >< rcvRes)
{
  url = "/stconf.nsf/WebAttendFrameset?OpenAgent&view=Attend&docID=$DOCID$&" +
        "meetingID=$MEETID$&join_type=mrc&subject=%3C/title%3E%3Cscript%3Ea" +
        "lert(%27VT-XSS-Test%27)%3C/script%3E%3C";

  if(http_vuln_check(port:http_port, url:url,
     pattern:"%3C/title%3E%3Cscript%3Ealert\(%27VT-XSS-Test%27\)%3C/script%3E%3C",
     extra_check:"IBM Lotus Sametime"))
  {
    report = http_report_vuln_url( port:http_port, url:url );
    security_message(port:http_port, data:report);
    exit(0);
  }
}
