# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807546");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-1652", "CVE-2016-1653", "CVE-2016-1651", "CVE-2016-1654",
                "CVE-2016-1655", "CVE-2016-1656", "CVE-2016-1657", "CVE-2016-1658",
                "CVE-2016-1659");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-04-18 16:52:03 +0530 (Mon, 18 Apr 2016)");
  script_name("Google Chrome Security Updates(stable-channel-update_13-2016-04)-Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A universal XSS in the browser's extension bindings.

  - An out-of-bounds write in Chrome's V8 JavaScript engine.

  - An out-of-bounds memory read issue in Pdfium JPEG2000 decoding.

  - An Uninitialized memory read in browser's media component.

  - An use-after-free in the extensions component.

  - A path restriction bypass in download implementation on Android.

  - An Address bar spoofing vulnerability.

  - The Extensions subsystem incorrectly relies on GetOrigin method calls for
    origin comparisons.

  - Multiple unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code,
  to obtain sensitive information and to cause denial of service or possibly
  have other impact via unknown vectors.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 50.0.2661.75 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  50.0.2661.75 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/04/stable-channel-update_13.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"50.0.2661.75"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"50.0.2661.75");
  security_message(data:report);
  exit(0);
}
