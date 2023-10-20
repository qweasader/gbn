# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150795");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-31 03:56:08 +0000 (Mon, 31 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-03 17:36:00 +0000 (Thu, 03 Aug 2023)");

  script_cve_id("CVE-2023-37467", "CVE-2023-37904", "CVE-2023-37906", "CVE-2023-38684",
                "CVE-2023-38685");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.1.x < 3.1.0.beta7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-37467: CSP nonce reuse vulnerability for anonymous users

  - CVE-2023-37904: Race Condition in Accept Invite

  - CVE-2023-37906: DoS via post edit reason

  - CVE-2023-38684: Possible DDoS due to unbounded limits in various controller actions

  - CVE-2023-38685: Restricted tag information visible to unauthenticated users");

  script_tag(name:"affected", value:"Discourse version 3.1.x prior to 3.1.0.beta7.");

  script_tag(name:"solution", value:"Update to version 3.1.0.beta7 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-gr5h-hm62-jr3j");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-6wj5-4ph2-c7qg");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-pjv6-47x6-mx7c");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-ff7g-xv79-hgmf");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-wx6x-q4gp-mgv5");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.1.0.beta", test_version_up: "3.1.0.beta7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.0.beta7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);