# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:fortinet:fortianalyzer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105815");
  script_version("2024-10-24T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-10-24 05:05:32 +0000 (Thu, 24 Oct 2024)");
  script_tag(name:"creation_date", value:"2016-07-19 10:34:06 +0200 (Tue, 19 Jul 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)");

  script_cve_id("CVE-2016-3196");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiAnalyzer Persistent XSS Vulnerability (FG-IR-16-014)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortianalyzer_version.nasl");
  script_mandatory_keys("fortianalyzer/version");

  script_tag(name:"summary", value:"Fortinet FortiAnalyzer is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When a low privileged user uploads images in the report
  section, the filenames are not properly sanitized.");

  script_tag(name:"affected", value:"Fortinet FortiAnalyzer version 5.0.0 through 5.0.11 and 5.2.0
  through 5.2.5.");

  script_tag(name:"solution", value:"Update to FortiAnalyzer 5.2.6, 5.4.0 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-014");
  script_xref(name:"Advisory-ID", value:"FG-IR-16-014");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.11") ||
    version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6 / 5.4.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
