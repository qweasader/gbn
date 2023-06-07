# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147779");
  script_version("2023-05-15T09:08:55+0000");
  script_tag(name:"last_modification", value:"2023-05-15 09:08:55 +0000 (Mon, 15 May 2023)");
  script_tag(name:"creation_date", value:"2022-03-09 02:33:53 +0000 (Wed, 09 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-14 12:32:00 +0000 (Mon, 14 Mar 2022)");

  script_cve_id("CVE-2021-41233", "CVE-2021-41239", "CVE-2021-41241");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 20.0.14, 21.x < 21.0.6, 22.x < 22.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-41233: Folder names of 'File Drop' share accessible

  - CVE-2021-41239: User enumeration setting not obeyed in User Status API

  - CVE-2021-41241: Groupfolders advanced permissions is not obeyed for subfolders");

  script_tag(name:"affected", value:"Nextcloud Server version 20.x and prior, version 21.x and
  22.x.");

  script_tag(name:"solution", value:"Update to version 20.0.14, 21.0.6, 22.2.1 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-26c8-35cm-xq9m");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-g722-cm3h-8wrx");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-m4wp-r357-4q94");

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

if (version_is_less(version: version, test_version: "20.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "21.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "22.0", test_version_up: "22.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
