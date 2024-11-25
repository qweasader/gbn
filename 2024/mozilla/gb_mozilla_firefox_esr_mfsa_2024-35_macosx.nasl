# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834454");
  script_version("2024-09-05T15:07:28+0000");
  script_cve_id("CVE-2024-7518", "CVE-2024-7520", "CVE-2024-7528");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 15:07:28 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 16:10:00 +0000 (Mon, 12 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-29 06:13:34 +0530 (Thu, 29 Aug 2024)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2024-35) - Mac OS X");

  script_tag(name:"summary", value:"Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-7518: Fullscreen notification dialog can be obscured by document content

  - CVE-2024-7520: Type confusion in WebAssembly

  - CVE-2024-7528: Use-after-free in IndexedDB");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code and perform spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  128.1 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 128.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-35/");
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

if(version_is_less(version:vers, test_version:"128.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
