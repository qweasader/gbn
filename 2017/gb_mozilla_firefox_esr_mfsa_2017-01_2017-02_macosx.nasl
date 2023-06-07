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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809878");
  script_version("2021-09-13T13:01:42+0000");
  script_cve_id("CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380",
                "CVE-2017-5390", "CVE-2017-5396", "CVE-2017-5383", "CVE-2017-5386",
                "CVE-2017-5373");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-13 13:01:42 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 19:35:00 +0000 (Thu, 02 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-01-27 12:11:29 +0530 (Fri, 27 Jan 2017)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2017-01_2017-02) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The excessive JIT code allocation allows bypass of ASLR and DEP.

  - An use-after-free in XSL.

  - The pointer and frame data leakage of Javascript objects.

  - The potential use-after-free during DOM manipulations.

  - An insecure communication methods in Developer Tools JSON viewer.

  - The Use-after-free with Media Decoder.

  - A location bar spoofing with unicode characters.

  - The webExtensions can use data: protocol to affect other extensions.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information,
  and to cause a denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR versions before 45.7.");

  script_tag(name:"solution", value:"Update to version 45.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-02");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"45.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"45.7", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);