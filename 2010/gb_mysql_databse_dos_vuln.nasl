###############################################################################
# OpenVAS Vulnerability Test
#
# MySQL 'ALTER DATABASE' Remote Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801380");
  script_version("2022-09-20T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_cve_id("CVE-2010-2008");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_name("MySQL 'ALTER DATABASE' Remote DoS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40333");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41198");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=53804");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jun/1024160.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-48.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl");
  script_mandatory_keys("MySQL/installed");

  script_tag(name:"summary", value:"MySQL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing the 'ALTER DATABASE' statement and
  can be exploited to corrupt the MySQL data directory using the '#mysql50#'
  prefix followed by a '.' or '..'.

  NOTE: Successful exploitation requires 'ALTER' privileges on a database.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to cause a Denial of Service.");

  script_tag(name:"affected", value:"MySQL version prior to 5.1.48.");

  script_tag(name:"solution", value:"Update to version 5.1.48 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

vers = eregmatch(pattern:"([0-9.a-z]+)", string:vers);
if(!isnull(vers[1])) {
  if(version_is_less(version:vers[1], test_version:"5.1.48")) {
    report = report_fixed_ver(installed_version:vers[1], fixed_version:"5.1.48");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
