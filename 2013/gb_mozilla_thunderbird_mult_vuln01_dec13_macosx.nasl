# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804044");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-5609", "CVE-2013-5613", "CVE-2013-5615", "CVE-2013-5616",
                "CVE-2013-5618", "CVE-2013-6671", "CVE-2013-6673");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 14:42:00 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-12-23 18:21:56 +0530 (Mon, 23 Dec 2013)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-01 Dec13 (Mac OS X)");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 24.2 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Use-after-free vulnerability in the PresShell::DispatchSynthMouseMove
  function.

  - JavaScript implementation does not properly enforce certain
  typeset restrictions on the generation of GetElementIC typed array stubs.

  - Use-after-free vulnerability in the nsEventListenerManager::HandleEvent
  SubType function

  - unspecified error in nsGfxScrollFrameInner::IsLTR function.

  - Flaw is due to the program ignoring the setting to remove the trust for
  extended validation (EV) capable root certificates.");
  script_tag(name:"affected", value:"Mozilla Thunderbird version before 24.2 on Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
attacks, bypass certain security restrictions, disclose potentially sensitive
information, and compromise a user's system.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56002");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64204");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64211");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64212");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64213");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64216");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-104.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"24.2"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.2");
  security_message(port: 0, data: report);
  exit(0);
}
