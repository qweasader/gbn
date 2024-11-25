# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131015");
  script_version("2024-08-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-08-28 05:05:33 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-21 12:31:42 +0000 (Wed, 21 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2024-43430");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 4.4.x < 4.4.2 Improper Access Control Vulnerability (MSA-24-0031)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to an improper access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Moodle lacks of access control when using external methods for
  Quiz overrides.");

  script_tag(name:"affected", value:"Moodle version 4.4.x prior to 4.4.2.");

  script_tag(name:"solution", value:"Update to version 4.4.2 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461198");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
