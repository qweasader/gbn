###############################################################################
# OpenVAS Vulnerability Test
#
# MariaDB Man-in-the-Middle Attack Vulnerability - Jun16 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808065");
  script_version("2022-08-08T10:24:51+0000");
  script_cve_id("CVE-2015-3152");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-08-08 10:24:51 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-04 19:47:00 +0000 (Thu, 04 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-06-02 18:10:39 +0530 (Thu, 02 Jun 2016)");
  script_name("MariaDB Man-in-the-Middle Attack Vulnerability - Jun16 (Windows)");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-7937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/show_bug.cgi?id=924663");

  script_tag(name:"summary", value:"MariaDB is prone to a man-in-the-middle (MITM) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to use of improper --ssl
  option when establishing a secure connection.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  man-in-the-middle attackers to spoof servers via a cleartext-downgrade
  attack.");

  script_tag(name:"affected", value:"MariaDB version 5.5.43 and earlier
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to version MariaDB 5.5.44 or
  later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!mariadbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mariadbVer = get_app_version(cpe:CPE, port:mariadbPort)){
  exit(0);
}

if(version_is_less(version:mariadbVer, test_version:"5.5.44"))
{
  report = report_fixed_ver(installed_version:mariadbVer, fixed_version:"5.5.44");
  security_message(data:report, port:mariadbPort);
  exit(0);
}

exit(99);