# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124190");
  script_version("2024-04-26T15:38:47+0000");
  script_tag(name:"last_modification", value:"2024-04-26 15:38:47 +0000 (Fri, 26 Apr 2024)");
  script_tag(name:"creation_date", value:"2022-10-03 10:42:12 +0000 (Mon, 03 Oct 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-06 19:07:00 +0000 (Thu, 06 Oct 2022)");

  script_cve_id("CVE-2022-36066");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 2.8.9, 2.9.x - 2.9.0.beta9 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Admins can upload a maliciously crafted Zip or Gzip Tar archive
  to write files at arbitrary locations and trigger remote code execution.");

  script_tag(name:"affected", value:"Discourse version prior to 2.8.9, 2.9.x through 2.9.0.beta9.");

  script_tag(name:"solution", value:"Update to version 2.8.9, 2.9.0.beta10 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-grvh-qcpg-hfmv");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.8.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.9.0.beta1", test_version2: "2.9.0.beta9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.0.beta10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
