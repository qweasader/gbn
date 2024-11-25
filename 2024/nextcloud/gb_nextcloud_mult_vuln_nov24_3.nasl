# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153499");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-21 15:09:55 +0000 (Thu, 21 Nov 2024)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:M/C:C/I:N/A:N");

  script_cve_id("CVE-2024-52513", "CVE-2024-52517");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 28.x < 28.0.11, 29.x < 29.0.8, 30.x < 30.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-52513: Attachments folder for Text app is accessible on 'Files drop' and 'Password
  protected' shares

  - CVE-2024-52517: Global credentials of external storages are sent back to the frontend");

  script_tag(name:"affected", value:"Nextcloud Server version 28.x prior to 28.0.11, 29.x prior to
  29.0.8 and 30.x prior to 30.0.1.");

  script_tag(name:"solution", value:"Update to version 28.0.11, 29.0.8, 30.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-gxph-5m4j-pfmj");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-x9q3-c7f8-3rcg");

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

if (version_in_range_exclusive(version: version, test_version_lo: "28.0.0", test_version_up: "28.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "28.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "29.0.0", test_version_up: "29.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "29.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "30.0.0", test_version_up: "30.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "30.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
