# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170474");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-05-17 09:49:53 +0000 (Wed, 17 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-18 21:48:00 +0000 (Sat, 18 Feb 2023)");

  script_cve_id("CVE-2022-2097", "CVE-2022-4304", "CVE-2022-4450", "CVE-2023-0215");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Agent 8.3.3 <= 8.3.4 Multiple Vulnerabilities (TNS-2023-13)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/detected");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to multiple vulnerabilities in
  OpenSSL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus Agent leverages third-party software to help provide
  underlying functionality. One third-party component (OpenSSL) was found to contain vulnerabilities,
  and updated versions have been made available by the providers.

  Nessus Agent 8.3.5 updates OpenSSL to version 1.1.1t address the identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus Agent version 8.3.3 through 8.3.4.");

  script_tag(name:"solution", value:"Update to version 8.3.5 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-13");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.3.3", test_version2: "8.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.5", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
