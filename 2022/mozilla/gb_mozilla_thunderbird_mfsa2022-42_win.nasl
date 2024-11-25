# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826477");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2022-40959", "CVE-2022-40960", "CVE-2022-40958", "CVE-2022-40956",
                "CVE-2022-40957", "CVE-2022-40962");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 02:59:00 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-09-22 16:05:16 +0530 (Thu, 22 Sep 2022)");
  script_name("Mozilla Thunderbird Security Advisory (MFSA2022-42) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Bypassing FeaturePolicy restrictions on transient pages.

  - Data-race when parsing non-UTF-8 URLs in threads.

  - Bypassing Secure Context restriction for cookies with __Host and __Secure prefix.

  - Content-Security-Policy base-uri bypass.

  - Incoherent instruction cache when building WASM on ARM64.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, and leak memory
  on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  102.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 102.3
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-42");
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

if(version_is_less(version:vers, test_version:"102.3"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.3", install_path:path);
  security_message(data:report);
  exit(0);
}
