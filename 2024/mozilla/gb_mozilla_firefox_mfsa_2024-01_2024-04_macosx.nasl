# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832656");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2024-0741", "CVE-2024-0742", "CVE-2024-0743", "CVE-2024-0744",
                "CVE-2024-0745", "CVE-2024-0754", "CVE-2024-0747", "CVE-2024-0748",
                "CVE-2024-0749", "CVE-2024-0750", "CVE-2024-0751", "CVE-2024-0752",
                "CVE-2024-0753", "CVE-2024-0755");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:00 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-24 17:30:21 +0530 (Wed, 24 Jan 2024)");
  script_name("Mozilla Firefox Security Advisories (MFSA2024-01, MFSA2024-04) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out of bounds write in ANGLE.

  - Failure to update user input timestamp.

  - Crash in NSS TLS method.

  - Wild pointer dereference in JavaScript.

  - Stack buffer overflow in WebAudio.

  - Bypass of Content Security Policy when directive unsafe-inline was set.

  - Compromised content process could modify document URI.

  - Phishing site popup could show local origin in address bar.

  - Potential permissions request bypass via clickjacking.

  - Privilege escalation through devtools.

  - Use-after-free could occur when applying update on macOS.

  - HSTS policy on subdomain could bypass policy of upper domain.

  - Crash when using some WASM files in devtools.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, to gain elevated
  privileges, conduct spoofing and cause denial of service on an affected
  system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  122 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 122 or later, Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-01/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"122")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"122", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}
