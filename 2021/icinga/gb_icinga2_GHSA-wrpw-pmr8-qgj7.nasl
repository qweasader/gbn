# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icinga:icinga2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146316");
  script_version("2024-11-15T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-15 05:05:36 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-07-19 02:27:51 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-27 18:36:00 +0000 (Tue, 27 Jul 2021)");

  script_cve_id("CVE-2021-32743");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icinga < 2.11.10, 2.12.0 < 2.12.5 Password Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_icinga2_http_detect.nasl");
  script_mandatory_keys("icinga2/detected");

  script_tag(name:"summary", value:"Icinga 2 is prone to a password disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Some of the Icinga 2 features that require credentials for
  external services exposed those through the API. The following features inadvertently exposed
  these credentials to authenticated API users with read permissions for the corresponding object
  types:

  - IdoMysqlConnection and IdoPgsqlConnection (every released version): password of the user used
  to connect to the database

  - IcingaDB (added in 2.12.0): password used to connect to the Redis server

  - ElasticsearchWriter (added in 2.8.0): password used to connect to the Elasticsearch server");

  script_tag(name:"impact", value:"An attacker who obtained these credentials can impersonate
  Icinga to these services and add, modify and delete information there.
  If credentials with more permissions are in use, this increases the impact accordingly.");

  script_tag(name:"affected", value:"Icinga2 prior to version 2.11.10 and 2.12.0 through 2.12.4.");

  script_tag(name:"solution", value:"Update to version 2.11.10, 2.12.5 or later.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/security/advisories/GHSA-wrpw-pmr8-qgj7");

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

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.11.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.11.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.12.0", test_version2: "2.12.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.12.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
