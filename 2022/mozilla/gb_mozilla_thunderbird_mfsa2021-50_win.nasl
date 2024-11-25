# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826443");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2021-38503", "CVE-2021-38504", "CVE-2021-43534", "CVE-2021-38506",
                "CVE-2021-38507", "CVE-2021-43535", "CVE-2021-38508", "CVE-2021-38509",
                "CVE-2021-43529", "CVE-2021-43527");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-13 19:53:00 +0000 (Mon, 13 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-09-09 17:16:29 +0530 (Fri, 09 Sep 2022)");
  script_name("Mozilla Thunderbird Security Advisory (MFSA2021-50) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - iframe sandbox rules did not apply to XSLT stylesheets.

  - Use-after-free in file picker dialog.

  - Thunderbird could be coaxed into going into fullscreen mode without notification or warning.

  - Opportunistic Encryption in HTTP2 could be used to bypass the Same-Origin-Policy on services hosted on other ports.

  - Use-after-free in HTTP2 Session object.

  - Permission Prompt could be overlaid, resulting in user confusion and potential spoofing.

  - Javascript alert box could have been spoofed onto an arbitrary domain.

  - Memory corruption when processing S/MIME messages.

  - NSS has a heap overflow when handling DER-encoded DSA or RSA-PSS signatures.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  91.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 91.3
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-50");
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

if(version_is_less(version:vers, test_version:"91.3"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"91.3", install_path:path);
  security_message(data:report);
  exit(0);
}
