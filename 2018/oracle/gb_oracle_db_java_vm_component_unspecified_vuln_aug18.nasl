# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813823");
  script_version("2021-09-07T08:17:19+0000");
  script_cve_id("CVE-2018-3110");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-07 08:17:19 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-08-13 15:10:36 +0530 (Mon, 13 Aug 2018)");
  script_name("Oracle Database Server 'Java VM' Component Unspecified Vulnerability");

  script_tag(name:"summary", value:"Oracle Database Server is prone to an unspecified security
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in component 'Java VM'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to affect
  confidentiality, integrity and availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions 11.2.0.4, 12.1.0.2 and 12.2.0.1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/alert-cve-2018-3110.html");
  script_xref(name:"URL", value:"https://blogs.oracle.com/oraclesecurity/security-alert-cve-2018-3110-released");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers == "11.2.0.4" ||
   vers == "12.1.0.2" ||
   vers == "12.2.0.1") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See reference", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(0);