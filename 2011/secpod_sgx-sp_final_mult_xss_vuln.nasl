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
  script_oid("1.3.6.1.4.1.25623.1.0.902532");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2010-3926");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("SGX-SP Final 'shop.cgi' Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://wb-i.net/soft1.HTML#spf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45752");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42857");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64593");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"SGX-SP Final version 10.0 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input passed to
  shop.cgi, which allows attackers to execute arbitrary HTML and script code
  in a user's browser session in context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to SGX-SP Final version 11.0 or later.");

  script_tag(name:"summary", value:"SGX-SP Final is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

foreach dir (make_list_unique("/SPF", "/shop", "/mall", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/shop.cgi",  port:port);

  ver = eregmatch(pattern:'SGX-SPF Ver([0-9.]+)', string:res);
  if(ver[1])
  {
    if(version_is_less(version:ver[1], test_version:"11.00"))
    {
      report = report_fixed_ver(installed_version:ver[1], fixed_version:"11.00");
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
