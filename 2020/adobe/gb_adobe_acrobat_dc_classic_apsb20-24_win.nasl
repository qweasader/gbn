# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:acrobat_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817024");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-9610", "CVE-2020-9612", "CVE-2020-9615", "CVE-2020-9597",
                "CVE-2020-9594", "CVE-2020-9614", "CVE-2020-9613", "CVE-2020-9596",
                "CVE-2020-9592", "CVE-2020-9611", "CVE-2020-9609", "CVE-2020-9608",
                "CVE-2020-9603", "CVE-2020-9602", "CVE-2020-9601", "CVE-2020-9600",
                "CVE-2020-9599", "CVE-2020-9605", "CVE-2020-9604", "CVE-2020-9607",
                "CVE-2020-9606", "CVE-2020-9598", "CVE-2020-9595", "CVE-2020-9593");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-30 19:36:00 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-14 11:57:34 +0530 (Thu, 14 May 2020)");
  script_name("Adobe Acrobat DC 2015 Security Update (APSB20-24) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC (Classic) 2015 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to following
  errors,

  - A null pointer error.

  - Heap overflow.

  - Race condition.

  - Out-of-bounds write.

  - Security bypass.

  - Stack exhaustion.

  - Out-of-bounds read.

  - Buffer error.

  - Use-after-free.

  - Invalid memory access.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial-of-service condition, execute arbitrary code,
  bypass security features and gain access to sensitive information");

  script_tag(name:"affected", value:"Adobe Acrobat DC 2015 (Classic) prior
  to version 2015.006.30523.");

  script_tag(name:"solution", value:"Update to Adobe Acrobat DC 2015 (Classic) to
  version 2015.006.30523 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-24.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Classic/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"15.0", test_version2:"15.006.30522")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.006.30523(2015.006.30523)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);