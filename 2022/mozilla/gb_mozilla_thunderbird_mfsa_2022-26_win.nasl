# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821157");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2022-34470", "CVE-2022-34468", "CVE-2022-2226", "CVE-2022-34481",
                "CVE-2022-31744", "CVE-2022-34472", "CVE-2022-34478", "CVE-2022-2200", "CVE-2022-34484");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 15:52:00 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-07-07 22:43:46 +0530 (Thu, 07 Jul 2022)");
  script_name("Mozilla Thunderbird Security Advisory (MFSA2022-26) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A popup window could be resized in a way to overlay the address bar with web content.

  - Use-after-free in nsSHistory.

  - CSP sandbox header without `allow-scripts` can be bypassed via retargeted javascript: URI.

  - An email with a mismatching OpenPGP signature date was accepted as valid.

  - Potential integer overflow in ReplaceElementsAt.

  - CSP bypass enabling stylesheet injection.

  - Unavailable PAC file resulted in OCSP requests being blocked.

  - Microsoft protocols can be attacked if a user accepts a prompt.

  - Undesired attributes could be set as part of prototype pollution.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  102 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 102
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-26");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102", install_path:path);
  security_message(data:report);
  exit(0);
}
