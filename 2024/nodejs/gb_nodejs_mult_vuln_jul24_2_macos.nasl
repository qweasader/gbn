# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152566");
  script_version("2024-07-10T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-09 01:42:33 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"cvss_base", value:"3.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2024-36137", "CVE-2024-22018", "CVE-2024-37372");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 20.x < 20.15.1, 21.x < 22.4.1 Multiple Vulnerabilities - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-36137: fs.fchown/fchmod bypasses permission model.

  - CVE-2024-22018: fs.lstat bypasses permission model.

  - CVE-2024-37372: Permission model improperly processes UNC paths.");

  script_tag(name:"affected", value:"Node.js versions 20.x and 22.x.");

  script_tag(name:"solution", value:"Update to version 20.15.1, 22.4.1 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/july-2024-security-releases");

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

if (version_in_range_exclusive(version: version, test_version_lo: "20.0", test_version_up: "20.15.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.15.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "22.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
