# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:std42:elfinder";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.152789");
  script_version("2024-08-02T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-08-02 05:05:39 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-01 03:20:16 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-38909");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("elFinder <= 2.1.64 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elfinder_detect.nasl");
  script_mandatory_keys("studio42/elfinder/detected");

  script_tag(name:"summary", value:"elFinder is prone to an access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Copying files with an unauthorized extension between server
  directories allows an arbitrary attacker to expose secrets, perform RCE, etc.");

  script_tag(name:"affected", value:"elFinder version 2.1.64 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 01st August, 2024.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/B0D0B0P0T/CVE/blob/main/CVE-2024-38909");

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

if (version_is_less_equal(version: version, test_version: "2.1.64")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
