# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143505");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2020-02-11 07:52:42 +0000 (Tue, 11 Feb 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-23 15:07:00 +0000 (Tue, 23 Feb 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-8654", "CVE-2020-8655");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eyes Of Network (EON) <= 5.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_eyesofnetwork_detect.nasl");
  script_mandatory_keys("eyesofnetwork/detected");

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Eyes Of Network (EON) is prone to multiple vulnerabilities:

  - OS command execution via AutoDiscovery module (CVE-2020-8654)

  - Privilege escalation vulnerability (CVE-2020-8655)");

  script_tag(name:"affected", value:"Eyes Of Network version 5.3 and probably prior.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://github.com/EyesOfNetworkCommunity/eonweb/issues/50");
  script_xref(name:"URL", value:"https://github.com/EyesOfNetworkCommunity/eonconf/issues/8");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/156266/EyesOfNetwork-5.3-Remote-Code-Execution.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See the referenced vendor advisories for a solution.");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
