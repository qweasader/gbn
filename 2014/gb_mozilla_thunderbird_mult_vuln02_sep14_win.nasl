# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804834");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-1565", "CVE-2014-1564", "CVE-2014-1563", "CVE-2014-1553");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-05 19:00:31 +0530 (Fri, 05 Sep 2014)");

  script_name("Mozilla Thunderbird Multiple Vulnerabilities-02 September14 (Windows)");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An out-of-bounds read error when creating an audio timeline in Web Audio.

  - An error when decoding GIF images.

  - A use-after-free error during cycle collection when animating SVG content.

  - Some other unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information and compromise a user's system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird 31.x before 31.1 on Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version
  31.1 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69523");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69524");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69525");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-67.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-68.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-69.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-70.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^31\.") {
  if(version_is_equal(version:vers, test_version:"31.0"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 31.0");
    security_message(port:0, data:report);
    exit(0);
  }
}
