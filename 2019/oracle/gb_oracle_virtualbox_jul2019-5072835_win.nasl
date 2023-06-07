# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815420");
  script_version("2021-10-07T07:48:17+0000");
  script_cve_id("CVE-2019-2863", "CVE-2019-1543", "CVE-2019-2867", "CVE-2019-2866",
                "CVE-2019-2865", "CVE-2019-2864", "CVE-2019-2848", "CVE-2019-2859",
                "CVE-2019-2850", "CVE-2019-2874", "CVE-2019-2875", "CVE-2019-2876",
                "CVE-2019-2877", "CVE-2019-2873");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-07 07:48:17 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 20:29:00 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-07-17 12:52:56 +0530 (Wed, 17 Jul 2019)");
  script_name("Oracle VirtualBox Security Updates (jul2019-5072835) - Windows");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified vulnerabilities in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation allows attacker to
  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"VirtualBox versions 6.x prior to 6.0.10
  and prior to 5.2.32 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version
  6.0.10 or 5.2.32 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Downloads");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version =~ "^6\." && version_is_less(version:version, test_version:"6.0.10")){
  fix = "6.0.10";
}

else if(version_is_less(version:version, test_version:"5.2.32")){
  fix = "5.2.32";
}

if(fix){
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
