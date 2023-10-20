# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112152");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-11 11:50:38 +0100 (Mon, 11 Dec 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 18:15:00 +0000 (Thu, 22 Apr 2021)");

  script_cve_id("CVE-2017-16921");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Remote Code Execution Vulnerability - Dec '17");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker who is logged into OTRS as an agent can manipulate form parameters
and execute arbitrary shell commands with the permissions of the OTRS or web server user.");

  script_tag(name:"affected", value:"OTRS 6.0.x up to and including 6.0.1, OTRS 5.0.x up to and including 5.0.24 and OTRS 4.0.x up to and including 4.0.26.");

  script_tag(name:"solution", value:"Upgrade to OTRS 4.0.27, 5.0.25, 6.0.2 or later.");

  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2017-09-security-update-otrs-framework/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.27");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.25");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.2");
  security_message(port: port, data: report);
  exit(0);
}


exit(0);
