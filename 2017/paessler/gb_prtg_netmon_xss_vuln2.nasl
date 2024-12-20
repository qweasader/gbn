# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:paessler:prtg_network_monitor';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140434");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-17 16:07:51 +0700 (Tue, 17 Oct 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-31 22:07:00 +0000 (Tue, 31 Oct 2017)");

  script_cve_id("CVE-2017-15008", "CVE-2017-15009", "CVE-2017-15651", "CVE-2017-15360", "CVE-2017-15917");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PRTG Network Monitor Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_prtg_network_monitor_detect.nasl");
  script_mandatory_keys("prtg_network_monitor/installed");

  script_tag(name:"summary", value:"PRTG Network Monitor is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"PRTG Network Monitor is prone to multiple cross-site scripting
vulnerabilities:

  - Stored Cross-Site Scripting on all sensor titles, related to incorrect error handling for a %00 in the SRC
attribute of an IMG element (CVE-2017-15008)

  - Reflected Cross-Site Scripting on error.htm (the error page), via the errormsg parameter (CVE-2017-15009)

  - Stored Cross-Site Scripting on all group names created, related to incorrect error handling for an HTML
encoded script (CVE-2017-15360)

  - Arbitrary remote code execution by remote authenticated administrators by uploading a .exe file and then
proceeding in spite of the error message (CVE-2017-15651)

  - it's possible to create a Map as a read-only user, by forging a request and sending it to the server
(CVE-2017-15917)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PRTG Network Monitor version 17.3.33.2830 and prior.");

  script_tag(name:"solution", value:"Update to version 17.4.35 or later.");

  script_xref(name:"URL", value:"https://medium.com/stolabs/security-issue-on-prtg-network-manager-ada65b45d37b");
  script_xref(name:"URL", value:"https://www.paessler.com/prtg/history/prtg-17#17.4.35");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "17.3.33.2830")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.4.35");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
