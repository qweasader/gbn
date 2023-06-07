# Copyright (C) 2008 Greenbone Networks GmbH
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900221");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_cve_id("CVE-2008-3963");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("MySQL Empty Bit-String Literal Denial of Service Vulnerability");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31769/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31081");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=35658");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-26.html");
  script_tag(name:"summary", value:"MySQL is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"insight", value:"Issue is due to error while processing an empty bit string literal via
  a specially crafted SQL statement.");
  script_tag(name:"affected", value:"MySQL versions prior to 5.0.x - 5.0.66,
  5.1.x - 5.1.26, and 6.0.x - 6.0.5 on all running platform.");
  script_tag(name:"solution", value:"Update to version 5.0.66 or 5.1.26 or 6.0.6 or later.");
  script_tag(name:"impact", value:"Successful exploitation by remote attackers could cause denying
  access to legitimate users.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE))
  exit(0);

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort))
  exit(0);

if(ereg(pattern:"^(5\.0(\.[0-5]?[0-9]|\.6[0-5])?|5\.1(\.[01]?[0-9]|" +
                "\.2[0-5])?|6\.0(\.[0-5])?)[^.0-9]", string:mysqlVer)){
  security_message(port:sqlPort);
}