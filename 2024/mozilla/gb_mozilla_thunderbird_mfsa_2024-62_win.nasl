# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834759");
  script_version("2024-11-21T05:05:26+0000");
  script_cve_id("CVE-2024-11159");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-21 05:05:26 +0000 (Thu, 21 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-19 14:56:37 +0000 (Tue, 19 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-14 12:35:19 +0530 (Thu, 14 Nov 2024)");
  script_name("Mozilla Thunderbird Security Update (mfsa_2024-62) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name: "insight" , value:"The flaw exists due to an error in
  handling remote content within OpenPGP-encrypted messages.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to disclose information.");

  script_tag(name: "affected" , value:"Mozilla Thunderbird prior to version
  132.0.1 on Windows.");

  script_tag(name: "solution" , value:"Update to version 132.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-62/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"132.0.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"132.0.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
