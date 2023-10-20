# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142499");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-06-11 04:18:55 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-14 04:29:00 +0000 (Fri, 14 Jun 2019)");

  script_cve_id("CVE-2019-12616");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin < 4.9.0 CSRF Vulnerability - PMASA-2019-4 (Linux)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a CSRF vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found that allows an attacker to trigger a CSRF attack
  against a phpMyAdmin user. The attacker can trick the user, for instance through a broken <img> tag pointing at
  the victim's phpMyAdmin database, and the attacker can potentially deliver a payload (such as a specific INSERT
  or DELETE statement) through the victim.");

  script_tag(name:"affected", value:"phpMyAdmin prior to version 4.9.0.");

  script_tag(name:"solution", value:"Update to version 4.9.0 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2019-4/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "4.9.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.0", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
