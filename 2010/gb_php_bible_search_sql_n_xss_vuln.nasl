###############################################################################
# OpenVAS Vulnerability Test
#
# PHP Bible Search 'bible.php' SQL Injection and Cross Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801401");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)");
  script_cve_id("CVE-2010-2616", "CVE-2010-2617");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP Bible Search 'bible.php' SQL Injection and Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41197");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59843");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.com/1006-exploits/phpbiblesearch-sqlxss.txt");

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to view, add,
  modify or delete information in the back-end database amd to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"PHP Bible Search version 0.99");

  script_tag(name:"insight", value:"Input passed to the 'chapter' parameter in 'bible.php' script is
  not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"PHP Bible Search is prone to SQL injection and cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/phpbiblesearch", "/" , http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/bible.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(">PHP Bible Search ::<" >< res) {
    req = http_get(item:string(dir, "/bible.php?string=&book=2&chapter=" +
                        "<script>alert('", vt_strings["lowercase"], "')</script>"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if((res =~ "^HTTP/1\.[01] 200" && vt_strings["lowercase"] >< res)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
