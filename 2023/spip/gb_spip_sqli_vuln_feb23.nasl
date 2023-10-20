# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:spip:spip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170330");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-02 13:24:03 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-09 15:41:00 +0000 (Thu, 09 Mar 2023)");

  script_cve_id("CVE-2023-24258");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SPIP 3.2.x < 3.2.17, 4.x < 4.0.9, 4.1.x < 4.1.7 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_spip_http_detect.nasl");
  script_mandatory_keys("spip/detected");

  script_tag(name:"summary", value:"SPIP is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SQL injection vulnerability via the _oups parameter allows
  attackers to execute arbitrary code via a crafted POST request.");

  script_tag(name:"affected", value:"SPIP version 3.2.x prior to 3.2.17, 4.x prior to 4.0.9 and
  4.1.x prior to 4.1.7.");

  script_tag(name:"solution", value:"Update to version 3.2.17, 4.0.9, 4.1.7 or later.");

  script_xref(name:"URL", value:"https://blog.spip.net/Mise-a-jour-de-securite-sortie-de-SPIP-4-1-7-SPIP-4-0-9-et-SPIP-3-2-17.html?lang=fr");
  script_xref(name:"URL", value:"https://github.com/Abyss-W4tcher/ab4yss-wr4iteups/blob/ffa980faa9e3598d49d6fb7def4f7a67cfb5f427/SPIP%20-%20Pentest/SPIP%204.1.5/SPIP_4.1.5_AND_BEFORE_AUTH_SQLi_Abyss_Watcher.md");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.2.0", test_version_up: "3.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0.0", test_version_up: "4.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1.0", test_version_up: "4.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
