# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900452");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-01-30 14:33:42 +0100 (Fri, 30 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5923", "CVE-2008-5924", "CVE-2008-5925");
  script_name("ASP-Dev XM Event Diary Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33152");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32809");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  in the context of the web application or can execute sql injection attack
  to gain sensitive information about the database engine and table structures.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"ASP-Dev XM Events Diary is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"- Input passed to the 'cat' parameter in 'default.asp' and 'diary_viewC.asp'
  are not properly sanitised before being used in SQL queries.

  - Insufficient access control to the database file 'diary.mdb' which is being
  used for Events Diary web application.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port))
  exit(0);

res = http_get_cache(item:"/diary/default.asp", port:port);
if("Powered by ASP-DEv XM Diary" >!< res) exit(0);

url = "/diary/default.asp?cat=testing'";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( "Microsoft JET Database Engine" >< res && "Syntax error in string" >< res){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
