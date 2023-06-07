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
  script_oid("1.3.6.1.4.1.25623.1.0.902476");
  script_cve_id("CVE-2011-4801");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ASAS Server End User Self Service (EUSS) SQL Injection Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to authenex database, dump all
  the OTP tokens, users information including credentials.");

  script_tag(name:"affected", value:"Authenex ASAS version 3.1.0.3 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'rgstcode' parameter in
  'akeyActivationLogin.do', is not properly sanitised before being used in SQL queries.");

  script_tag(name:"summary", value:"Authenex ASAS is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/46103");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105287/authenex-sql.txt");
  script_xref(name:"URL", value:"http://support.authenex.com/index.php?_m=downloads&_a=viewdownload&downloaditemid=125");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:5080);

res = http_get_cache(item:"/initial.do", port:port);

if('ASAS Web Management Console Login' >< res)
{
  asVer = eregmatch(pattern:"ASAS Web Management Console v([0-9.]+)",
                    string:res);

  if(!isnull(asVer[1]))
  {
    if(version_is_less_equal(version:asVer[1], test_version:"3.1.0.3")){
      report = report_fixed_ver(installed_version:asVer[1], vulnerable_range:"Less than or equal to 3.1.0.3");
      security_message(port: port, data: report);
    }
  }
}
