# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128045");
  script_version("2024-09-12T07:59:53+0000");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-08-05 16:00:20 +0000 (Mon, 05 Aug 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-11 14:39:12 +0000 (Wed, 11 Sep 2024)");

  script_cve_id("CVE-2024-7437", "CVE-2024-7438");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Simple Machines Forum <= 2.1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
  script_mandatory_keys("SMF/installed");

  script_tag(name:"summary", value:"Simple Machines Forum is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target
  host.");

  script_tag(name:"insight", value: "The following flaws exist:

  - CVE-2024-7437: The component 'Delete User Handler' of the file 'index.php?action=profile,u=2,
  area=showalerts,do=remove' is affected with Resource Injection Vulnerability.

  - CVE-2004-7438: The component 'User Alert Read Status Handler' of the file 'index.php?action=
  profile,u=2,area=showalerts,do=read' is affected with Resource Injection Vulnerability.");

  script_tag(name:"affected", value:"Simple Machines Forum through version 2.1.4.");

  script_tag(name:"solution", value:"No known solution is available as of 09th August, 2024.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/Fewword/Poc/blob/main/smf/smf-poc1.md");
  script_xref(name:"URL", value:"https://github.com/Fewword/Poc/blob/main/smf/smf-poc2.md");

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

if (version_is_less_equal(version: version, test_version: "2.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);