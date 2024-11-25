# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818108");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2021-29945");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-30 19:01:00 +0000 (Wed, 30 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-04-20 16:16:42 +0530 (Tue, 20 Apr 2021)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2021-13, MFSA2021-16) - 01 - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the WebAssembly JIT could
  miscalculate the size of a return type.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  78.10 on Windows x86-32 platforms.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox ESR version
  78.10 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-15/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!os_arch = get_kb_item("SMB/Windows/Arch")){
  exit(0);
}

if("x86" >!< os_arch){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"78.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"78.10", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
