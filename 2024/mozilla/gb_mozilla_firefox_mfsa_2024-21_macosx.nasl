# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834012");
  script_version("2024-11-08T05:05:30+0000");
  script_cve_id("CVE-2024-4764", "CVE-2024-4367", "CVE-2024-4767", "CVE-2024-4768",
                "CVE-2024-4769", "CVE-2024-4770", "CVE-2024-4771", "CVE-2024-4772",
                "CVE-2024-4773", "CVE-2024-4774", "CVE-2024-4775", "CVE-2024-4776",
                "CVE-2024-4777", "CVE-2024-4778", "CVE-2024-10941");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-11-08 05:05:30 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-05-17 10:46:05 +0530 (Fri, 17 May 2024)");
  script_name("Mozilla Firefox Security Update (mfsa_2024-21) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-4764: Use-after-free when audio input connected with multiple consumers.

  - CVE-2024-4367: Arbitrary JavaScript execution in PDF.js.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code, conduct spoofing and denial of dervice attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox prior to version 126 on
  Mac OS X.");

  script_tag(name:"solution", value:"Update to version 126 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-21/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"126")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"126", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
