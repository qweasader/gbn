# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804095");
  script_version("2023-11-02T05:05:26+0000");
  script_cve_id("CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479", "CVE-2014-1480",
                "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1485",
                "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488", "CVE-2014-1490",
                "CVE-2014-1491");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-21 18:37:00 +0000 (Fri, 21 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-02-11 19:46:21 +0530 (Tue, 11 Feb 2014)");
  script_name("SeaMonkey Multiple Vulnerabilities-01 Feb14 (Mac OS X)");

  script_tag(name:"summary", value:"SeaMonkey is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error when handling XML Binding Language (XBL) content scopes.

  - An error when handling discarded images within the 'RasterImage' class.

  - An error related to the 'document.caretPositionFromPoint()' and
  'document.elementFromPoint()' functions.

  - An error when handling XSLT stylesheets.

  - A use-after-free error related to certain content types when used with the
  'imgRequestProxy()' function.

  - An error when handling web workers error messages.

  - An error when terminating a web worker running asm.js code after passing an
  object between threads.

  - A race condition error when handling session tickets within libssl.

  - An error when handling JavaScript native getters on window objects.

  - Additionally, a weakness exists when handling the dialog for saving downloaded
  files.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.24 on Mac OS X");
  script_tag(name:"solution", value:"Upgrade to SeaMonkey version 2.24 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65316");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65317");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65321");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65322");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65324");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65326");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65328");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65330");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65331");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65332");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65334");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65335");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:smVer, test_version:"2.24"))
{
  report = report_fixed_ver(installed_version:smVer, fixed_version:"2.24");
  security_message(port:0, data:report);
  exit(0);
}
