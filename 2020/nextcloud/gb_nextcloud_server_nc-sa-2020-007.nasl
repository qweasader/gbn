# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143458");
  script_version("2023-05-15T09:08:55+0000");
  script_tag(name:"last_modification", value:"2023-05-15 09:08:55 +0000 (Mon, 15 May 2023)");
  script_tag(name:"creation_date", value:"2020-02-05 07:47:41 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-06 18:22:00 +0000 (Thu, 06 Feb 2020)");

  script_cve_id("CVE-2019-15618");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 14.0.9, < 15.0.6 XSS Vulnerability (NC-SA-2020-007)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to reflected cross-site scripting vulnerability.");

  script_tag(name:"insight", value:"Missing escaping of HTML in the Updater of Nextcloud allows a reflected XSS
  when starting the updater from a malicious location.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Nextcloud server versions prior 14.0.9 and prior 15.0.6.");

  script_tag(name:"solution", value:"Update to version 14.0.9, 15.0.6 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2020-007");

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

if (version_is_less(version: version, test_version: "14.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "15.0.0", test_version2: "15.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
