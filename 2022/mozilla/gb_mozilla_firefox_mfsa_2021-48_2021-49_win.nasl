# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820042");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2021-38503", "CVE-2021-38504", "CVE-2021-43534", "CVE-2021-38506",
                "CVE-2021-38507", "CVE-2021-43533", "CVE-2021-38508", "CVE-2021-43531",
                "CVE-2021-43532", "CVE-2021-38509");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-13 19:53:00 +0000 (Mon, 13 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-03-28 16:55:44 +0530 (Mon, 28 Mar 2022)");
  script_name("Mozilla Firefox Security Advisories (MFSA2021-48, MFSA2021-49) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - iframe sandbox rules did not apply to XSLT stylesheets.

  - Use-after-free in file picker dialog.

  - Firefox could be coaxed into going into fullscreen mode without notification or warning.

  - Opportunistic Encryption in HTTP2 could be used to bypass the Same-Origin-Policy on services hosted on other ports.

  - Permission Prompt could be overlaid, resulting in user confusion and potential spoofing.

  - Web Extensions could access pre-redirect URL when their context menu was triggered by a user.

  - Javascript alert box could have been spoofed onto an arbitrary domain.

  - 'Copy Image Link' context menu action could have been abused to see authentication tokens.

  - URL Parsing may incorrectly parse internationalized domains.

  - Memory safety bugs fixed in Firefox 94 and Firefox ESR 91.3.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service, bypass authentication
  and conduct spoofing attack etc.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  94 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 94
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-48/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"94"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"94", install_path:path);
  security_message(data:report);
  exit(0);
}
