# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.819968");
  script_version("2022-01-26T03:03:43+0000");
  script_cve_id("CVE-2022-21394", "CVE-2022-21295");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-01-26 03:03:43 +0000 (Wed, 26 Jan 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-25 04:00:00 +0000 (Tue, 25 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-19 23:52:36 +0530 (Wed, 19 Jan 2022)");
  script_name("Oracle VirtualBox Security Update(Jan2022) - Linux");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple unspecified
  errors in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality.");

  script_tag(name:"affected", value:"VirtualBox versions 6.1.x prior to 6.1.32
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version 6.1.32
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2022.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^6\.1\." && version_is_less(version:vers, test_version:"6.1.32"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.1.32", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
