# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:plone:plone";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126603");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-03-11 09:07:06 +0000 (Mon, 11 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-22889");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Hotfix not detected

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Plone CMS <= 6.0.9 Incorrect Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_plone_http_detect.nasl");
  script_mandatory_keys("plone/detected");

  script_tag(name:"summary", value:"Plone CMS is prone to an incorrect access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Plone CMS allows to incorrect access control which makes it
  possible for remote attacker to view and list all files hosted on the website via sending a
  crafted request.");

  script_tag(name:"affected", value:"Plone CMS version 6.0.9 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 15th April, 2024.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-xg5p-8wg5-rhxm");

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

if(version_is_less_equal(version: version, test_version: "6.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
