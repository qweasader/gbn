# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826471");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2022-3033", "CVE-2022-3032", "CVE-2022-3034");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-03 20:22:00 +0000 (Tue, 03 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-09-21 13:42:30 +0530 (Wed, 21 Sep 2022)");
  script_name("Mozilla Thunderbird Security Advisory (MFSA2022-39) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Leaking of sensitive information when composing a response to an HTML email
  with a META refresh tag.

  - Remote content specified in an HTML document that was nested inside an
  iframe's srcdoc attribute was not blocked.

  - An iframe element in an HTML email could trigger a network request.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, disclose information, and cause a denial
  of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  91.13.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version
  91.13.1 or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-39");
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

if(version_is_less(version:vers, test_version:"91.13.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"91.13.1", install_path:path);
  security_message(data:report);
  exit(0);
}
