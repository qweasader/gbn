###############################################################################
# OpenVAS Vulnerability Test
#
# Transform Foundation Server Multiple Cross Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.804637");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-2577");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-06-12 12:37:47 +0530 (Thu, 12 Jun 2014)");
  script_name("Transform Foundation Server Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"Transform Foundation Server is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an:

  - Improper validation of input passed via 'db' and 'referer' POST
  parameters passed to /index.fsp/index.fsp script.

  - Improper validation of the input passed via 'pn' GET parameter passed to
  /index.fsp script.

  - Improper validation of input passed via the URL before returning it to
  users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  script code in a user's browser session within the trust relationship
  between their browser and the server.");

  script_tag(name:"affected", value:"Transform Foundation Server version 4.3.1 and 5.2");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Jun/34");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67810");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126907");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2014/06/cve-2014-2577-xss-on-transform.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

serPort = http_get_port(default:80);

foreach dir (make_list_unique("/", "/FoundationServer", "/TFS", http_cgi_dirs(port:serPort)))
{

  if(dir == "/") dir = "";

  req = http_get(item:string(dir, "/Presenter/index.fsp?signout=true"), port:serPort);
  res = http_keepalive_send_recv(port:serPort, data:req);

  if("Bottomline Technologies" >< res && "Transform Content" >< res)
  {
    url = dir + "/TransformContentCenter/index.fsp/document.pdf?pn=<script>" +
          "alert(document.cookie);</script>";

    if(http_vuln_check(port:serPort, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\);</script>",
                extra_check: "unexpected error"))
    {
      security_message(port:serPort);
      exit(0);
    }
  }
}

exit(99);
