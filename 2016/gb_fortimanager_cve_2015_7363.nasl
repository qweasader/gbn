# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:fortinet:fortimanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106344");
  script_version("2024-10-29T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"creation_date", value:"2016-10-11 12:51:08 +0700 (Tue, 11 Oct 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");

  script_cve_id("CVE-2015-7363");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiManager XSS Vulnerability (FG-IR-16-051)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortimanager_version.nasl");
  script_mandatory_keys("fortimanager/version");

  script_tag(name:"summary", value:"Fortinet FortiManager is prone to a cross-site-scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A cross-site-scripting vulnerability in FortiManager in
  advanced settings page could allow an administrator to inject scripts in the add filter field.");

  script_tag(name:"impact", value:"An administrator could inject inject arbitrary web scripts.");

  script_tag(name:"affected", value:"Fortinet FortiManager 5.0.0 through 5.0.11 and 5.2.0 through
  5.2.2.");

  script_tag(name:"solution", value:"Update to FortiManager 5.0.12, 5.2.3, 5.4.0 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-051");
  script_xref(name:"Advisory-ID", value:"FG-IR-16-051");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.12");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
