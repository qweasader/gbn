###############################################################################
# OpenVAS Vulnerability Test
#
# SeaMonkey Multiple Vulnerabilities-01 Mar14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804528");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1496", "CVE-2014-1497",
                "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502",
                "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509",
                "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513",
                "CVE-2014-1514");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 13:48:00 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-03-27 13:03:47 +0530 (Thu, 27 Mar 2014)");
  script_name("SeaMonkey Multiple Vulnerabilities-01 Mar14 (Windows)");


  script_tag(name:"summary", value:"SeaMonkey is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Local users can gain privileges by modifying the extracted Mar contents
  during an update.

  - A boundary error when decoding WAV audio files.

  - The crypto.generateCRMFRequest method does not properly validate a certain
  key type.

  - An error related to certain WebIDL-implemented APIs.

  - An error when performing polygon rendering in MathML.

  - The session-restore feature does not consider the Content Security Policy of
  a data URL.

  - A timing error when processing SVG format images with filters and
  displacements.

  - A use-after-free error when handling garbage collection of TypeObjects under
  memory pressure.

  - An error within the TypedArrayObject implementation when handling neutered
  ArrayBuffer objects.

  - And some unspecified errors exist.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct spoofing attacks,
disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.25 on Windows");
  script_tag(name:"solution", value:"Upgrade to SeaMonkey version 2.25 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57500");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66412");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66417");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66418");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66422");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66429");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:smVer, test_version:"2.25"))
{
  report = report_fixed_ver(installed_version:smVer, fixed_version:"2.25");
  security_message(port:0, data:report);
  exit(0);
}
