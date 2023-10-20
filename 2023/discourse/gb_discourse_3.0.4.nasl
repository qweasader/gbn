# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149800");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-15 04:10:36 +0000 (Thu, 15 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-22 21:06:00 +0000 (Thu, 22 Jun 2023)");

  script_cve_id("CVE-2023-31142", "CVE-2023-32061", "CVE-2023-32301", "CVE-2023-34250");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 3.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-31142: General category permissions could be set back to default

  - CVE-2023-32061: Topic creation page allows iFrame tag without restrictions

  - CVE-2023-32301: Canonical url not being used for topic embeddings

  - CVE-2023-34250: Exposure of number of topics recently created in private categories");

  script_tag(name:"affected", value:"Discourse prior to 3.0.4.");

  script_tag(name:"solution", value:"Update to version 3.0.4 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-286w-97m2-78x2");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-prx4-49m8-874g");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-p2jx-m2j5-hqh4");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-q8m5-wmjr-3ppg");

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

if (version_is_less(version: version, test_version: "3.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
