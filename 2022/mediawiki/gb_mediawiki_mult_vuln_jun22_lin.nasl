# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126044");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2022-06-17 10:29:41 +0000 (Fri, 17 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-29 18:47:00 +0000 (Wed, 29 Dec 2021)");

  script_cve_id("CVE-2021-45471", "CVE-2021-45472", "CVE-2021-45473", "CVE-2021-45474");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki <= 1.37 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2021-45471: An attacker can edit an EntitySchema item using a globally blocked IP.
  This might lead to an unauthorized edit of label, description and alias.

  CVE-2021-45472: An attacker can specify a URL format in an external identifier property
  using a formatter URL with a string like $1 and then use the external
  identifier property in an item to substitute a string into the URL.

  CVE-2021-45473: An attacker can create or edit existing items. This might lead to an unexpected
  information leak.

  CVE-2021-45474: Any valid import source followed by a payload without spaces
  (as spaces are replaced with underscores) is unescaped and interpreted as actual HTML.");

  script_tag(name:"affected", value:"MediaWiki version 1.37 and prior.");

  script_tag(name:"solution", value:"Update to version 1.38 or later.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T296578");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T297570");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T294693");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T296605");

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

if (version_is_less_equal(version: version, test_version: "1.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
