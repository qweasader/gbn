###############################################################################
# OpenVAS Vulnerability Test
#
# AdPeeps 'index.php' Multiple Vulnerabilities.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801414");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-4939", "CVE-2009-4943", "CVE-2009-4945");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AdPeeps 'index.php' Multiple Vulnerabilities.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35262");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50824");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50822");
  script_xref(name:"URL", value:"http://forum.intern0t.net/intern0t-advisories/1049-adpeeps-8-5d1-cross-site-scripting-html-injection-vulnerabilities.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in the
  context of an affected site when malicious data is viewed.");

  script_tag(name:"affected", value:"Adpeeps version 8.6.5d1 and prior.");

  script_tag(name:"insight", value:"The flaws are due to

  - Improper validation of user supplied data to the 'index.php' page via
  various parameters.

  - 'view_adrates' action with an invalid uid parameter, in 'index.php' reveals
  the installation path in an error message.

  - Application having a default password of 'admin' for the 'admin' account,
  which makes it easier for remote attackers to obtain access via requests
  to 'index.php'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"AdPeeps is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port)) exit(0);

foreach path (make_list_unique("/", "/adpeeps", http_cgi_dirs(port:port)))
{

  if(path == "/") path = "";

  res = http_get_cache(item:string(path, "/index.php"), port:port);

  if(">Ad Peeps" >< res ||
     ">Advertisement Management Control Panel<" >< res)
  {
    req = http_get(item:string(path,
                     "/index.php?loc=view_adrates&uid=1000000"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if("mysql_result()" >< res &&
       "Unable to jump to row 0 on MySQL result" >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
