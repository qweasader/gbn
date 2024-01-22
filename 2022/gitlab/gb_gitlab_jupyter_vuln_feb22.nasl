# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147964");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-04-11 07:09:03 +0000 (Mon, 11 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 19:16:00 +0000 (Mon, 04 Apr 2022)");

  script_cve_id("CVE-2022-0427");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 14.5.x < 14.5.4, 14.6.x < 14.6.4, 14.7.x < 14.7.1 Jupyter Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a vulnerability in the Jupyter Notebooks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Missing sanitization of HTML attributes in Jupyter notebooks
  allows an attacker to perform arbitrary HTTP POST requests on a user's behalf leading to
  potential account takeover.");

  script_tag(name:"affected", value:"GitLab version 14.5.x through 14.5.3, 14.6.x through 14.6.3 and
  14.7.0.");

  script_tag(name:"solution", value:"Update to version 14.5.4, 14.6.4, 14.7.1 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/02/03/security-release-gitlab-14-7-1-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "14.5", test_version_up: "14.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.5.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.6", test_version_up: "14.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.6.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.7", test_version_up: "14.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.7.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
