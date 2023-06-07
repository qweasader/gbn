# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812284");
  script_version("2021-09-09T14:06:19+0000");
  script_cve_id("CVE-2017-7156", "CVE-2017-7157", "CVE-2017-7160", "CVE-2017-13856",
                "CVE-2017-13866", "CVE-2017-13870", "CVE-2017-5753", "CVE-2017-5715",
                "CVE-2017-7161", "CVE-2017-13885", "CVE-2017-7165", "CVE-2017-13884",
                "CVE-2017-7153");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-22 19:20:00 +0000 (Fri, 22 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-12-28 14:26:04 +0530 (Thu, 28 Dec 2017)");
  script_name("Apple Safari Security Update (HT208324) - Mac OS X");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple remote code execution (RCE)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  memory corruption issues, command injection issue in Web Inspector, redirect
  responses to '401 Unauthorized' and other multiple errors leading to 'speculative
  execution side-channel attacks' that affect many modern processors and
  operating systems including Intel, AMD, and ARM.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code or
  cause a denial of service or gain access to potentially sensitive information
  or spoof user interface.");

  script_tag(name:"affected", value:"Apple Safari versions before 11.0.2");

  script_tag(name:"solution", value:"Update to version 11.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208324");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208403");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"11.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.0.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);