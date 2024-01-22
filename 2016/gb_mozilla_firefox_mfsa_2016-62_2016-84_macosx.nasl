# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808641");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2016-5250", "CVE-2016-5268", "CVE-2016-5266", "CVE-2016-2835",
                "CVE-2016-5265", "CVE-2016-5264", "CVE-2016-5263", "CVE-2016-2837",
                "CVE-2016-5262", "CVE-2016-5261", "CVE-2016-5260", "CVE-2016-5259",
                "CVE-2016-5258", "CVE-2016-5255", "CVE-2016-5254", "CVE-2016-5253",
                "CVE-2016-0718", "CVE-2016-5252", "CVE-2016-5251", "CVE-2016-2838",
                "CVE-2016-2830", "CVE-2016-2836");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-08-08 14:54:29 +0530 (Mon, 08 Aug 2016)");
  script_name("Mozilla Firefox Security Update (mfsa_2016-62_2016-84) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist. Please see the references for more details.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to spoof the address bar, to bypass the same origin
  policy, and conduct Universal XSS (UXSS) attacks, to read arbitrary files, to
  execute arbitrary code, to cause a denial of service, to discover cleartext
  passwords by reading a session restoration file and to obtain sensitive information.");

  script_tag(name:"affected", value:"Mozilla Firefox versions before 48.");

  script_tag(name:"solution", value:"Update to version 48 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-84/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-83/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-82/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-81/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-80/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"48")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"48", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);