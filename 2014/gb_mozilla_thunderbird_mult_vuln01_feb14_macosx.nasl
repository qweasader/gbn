###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Multiple Vulnerabilities-01 Feb14 (Mac OS X)
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804093");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1481", "CVE-2014-1482",
                "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1490", "CVE-2014-1491");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-07 19:37:00 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-02-11 19:36:46 +0530 (Tue, 11 Feb 2014)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-01 Feb14 (Mac OS X)");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error when handling XML Binding Language (XBL) content scopes.

  - An error when handling discarded images within the 'RasterImage' class.

  - A use-after-free error related to certain content types when used with the
  'imgRequestProxy()' function.

  - An error when handling web workers error messages.

  - A race condition error when handling session tickets within libssl.

  - An error when handling JavaScript native getters on window objects.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system.");
  script_tag(name:"affected", value:"Mozilla Thunderbird version before 24.3 on Mac OS X");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 24.3 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65317");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65326");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65328");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65330");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65332");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65334");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65335");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"24.3"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.3");
  security_message(port:0, data:report);
  exit(0);
}
