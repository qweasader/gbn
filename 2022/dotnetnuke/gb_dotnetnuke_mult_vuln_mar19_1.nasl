# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:dnnsoftware:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126105");
  script_version("2023-04-27T12:17:38+0000");
  script_tag(name:"last_modification", value:"2023-04-27 12:17:38 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"creation_date", value:"2022-08-08 10:04:16 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 20:46:00 +0000 (Fri, 03 Mar 2023)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-18325", "CVE-2018-18326");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DotNetNuke < 9.3.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_http_detect.nasl");
  script_mandatory_keys("dotnetnuke/detected");

  script_tag(name:"summary", value:"DotNetNuke is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-18325: Usage of a weak encryption algorithm to protect input parameters. NOTE: this
  issue exists because of an incomplete fix for CVE-2018-15811.

  - CVE-2018-18326: Incorrect conversion of encryption key source values, resulting in lower than
  expected entropy. NOTE: this issue exists because of an incomplete fix for CVE-2018-15812.");

  script_tag(name:"affected", value:"DotNetNuke prior to version 9.3.0.");

  script_tag(name:"solution", value:"Update to version 9.3.0 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-j3g9-6fx5-gjv7");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-xx3h-j3cx-8qfj");
  script_xref(name:"URL", value:"https://dnncommunity.org/security");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "9.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
