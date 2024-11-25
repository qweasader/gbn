# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832009");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2023-25728", "CVE-2023-25730", "CVE-2023-0767", "CVE-2023-25746",
                "CVE-2023-25735", "CVE-2023-25737", "CVE-2023-25739", "CVE-2023-25744",
                "CVE-2023-25729", "CVE-2023-25732", "CVE-2023-25742");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 17:11:00 +0000 (Thu, 08 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-03-03 12:02:24 +0530 (Fri, 03 Mar 2023)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2023-05, MFSA2023-06) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Content security policy leak in violation reports using iframes.

  - Screen hijack via browser fullscreen mode.

  - Arbitrary memory write via PKCS 12 in NSS.

  - Potential use-after-free from compartment mismatch in SpiderMonkey.

  - Invalid downcast in SVGUtils::SetupStrokeGeometry.

  - Use-after-free in mozilla::dom::ScriptLoadContext::~ScriptLoadContext.

  - Extensions could have opened external schemes without user knowledge.

  - Out of bounds memory write from EncodeInputStream.

  - Web Crypto ImportKey crashes tab.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, disclose sensitive information and
  conduct spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  102.8 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 102.8
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-06/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102.8"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.8", install_path:path);
  security_message(data:report);
  exit(0);
}
