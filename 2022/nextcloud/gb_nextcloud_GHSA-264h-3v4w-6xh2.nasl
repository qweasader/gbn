# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148394");
  script_version("2023-05-15T09:08:55+0000");
  script_tag(name:"last_modification", value:"2023-05-15 09:08:55 +0000 (Mon, 15 May 2023)");
  script_tag(name:"creation_date", value:"2022-07-06 04:44:52 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-14 11:45:00 +0000 (Thu, 14 Jul 2022)");

  script_cve_id("CVE-2022-31014");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 22.2.8, 23.x < 23.0.5, 24.x < 24.0.1 Command Injection Vulnerability (GHSA-264h-3v4w-6xh2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an SMTP command injection
  vulnerability in iCalendar Attachments to emails via newlines.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The impact varies based on which commands are supported by the
  backend SMTP server. However, the main risk here is that the attacker can then hijack an
  already-authenticated SMTP session and run arbitrary SMTP commands as the email user, such as
  sending emails to other users, changing the FROM user, and so on. As before, this depends on the
  configuration of the server itself, but newlines should be sanitized to mitigate such arbitrary
  SMTP command injection.");

  script_tag(name:"affected", value:"Nextcloud Server prior to version 22.2.8, version 23.x through
  23.0.4 and version 24.0.0.");

  script_tag(name:"solution", value:"Update to version 22.2.8, 23.0.5, 24.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-264h-3v4w-6xh2");

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

if (version_is_less(version: version, test_version: "22.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "23.0", test_version_up: "23.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "24.0", test_version_up: "24.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
