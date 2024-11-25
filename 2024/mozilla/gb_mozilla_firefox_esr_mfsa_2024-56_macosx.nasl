# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834726");
  script_version("2024-11-12T05:05:34+0000");
  script_cve_id("CVE-2024-10460", "CVE-2024-10461", "CVE-2024-10462", "CVE-2024-10464",
                "CVE-2024-10465", "CVE-2024-10466", "CVE-2024-10467");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-04 13:26:32 +0000 (Mon, 04 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-07 11:12:45 +0530 (Thu, 07 Nov 2024)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2024-56) - Mac OS X");

  script_tag(name:"summary", value:"Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-10462: Origin of permission prompt could be spoofed by long URL

  - CVE-2024-10460: Confusing display of origin for external protocol handler prompt");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution, disclose information, conduct spoofing and
  denial of service attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  128.4 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 128.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-56/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"128.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
