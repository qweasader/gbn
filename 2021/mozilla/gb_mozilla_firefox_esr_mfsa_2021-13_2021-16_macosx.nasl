# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818101");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2021-23994", "CVE-2021-23995", "CVE-2021-23998", "CVE-2021-23961",
                "CVE-2021-23999", "CVE-2021-24002", "CVE-2021-29946");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-02 16:55:00 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-04-20 16:16:42 +0530 (Tue, 20 Apr 2021)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2021-13_2021-16) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An out of bound write due to lazy initialization.

  - An use-after-free in Responsive Design Mode.

  - Secure Lock icon could have been spoofed.

  - More internal network hosts could have been probed by a malicious webpage.

  - Blob URLs may have been granted additional privileges.

  - Arbitrary FTP command execution on FTP servers using an encoded URL.

  - Port blocking could be bypassed.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, escalate privileges and bypass security
  restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  78.10 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 78.10
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-15/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"78.10"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"78.10", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
