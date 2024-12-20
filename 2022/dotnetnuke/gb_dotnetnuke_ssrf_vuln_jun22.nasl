# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:dnnsoftware:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124078");
  script_version("2023-06-09T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-06-09 05:05:15 +0000 (Fri, 09 Jun 2023)");
  script_tag(name:"creation_date", value:"2022-06-08 05:20:48 +0000 (Wed, 08 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-09 17:07:00 +0000 (Thu, 09 Jun 2022)");

  script_cve_id("CVE-2021-40186");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("DotNetNuke <= 9.11.2 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_http_detect.nasl");
  script_mandatory_keys("dotnetnuke/detected");

  script_tag(name:"summary", value:"DotNetNuke is prone to a server-side request forgery (SSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In the most common scenario, the attacker exploits SSRF
  vulnerabilities to attack systems behind the firewall and access sensitive information from Cloud
  Provider metadata services.");

  script_tag(name:"affected", value:"DotNetNuke (DNN) version 9.11.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://appcheck-ng.com/dnn-cms-server-side-request-forgery-cve-2021-40186");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "9.11.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
