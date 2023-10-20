# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/o:intel:active_management_technology_firmware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141479");
  script_version("2023-08-18T16:09:48+0000");
  script_tag(name:"last_modification", value:"2023-08-18 16:09:48 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-09-14 14:46:25 +0700 (Fri, 14 Sep 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 20:09:00 +0000 (Wed, 26 May 2021)");

  script_cve_id("CVE-2018-3616", "CVE-2018-3657", "CVE-2018-3658");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Multiple Vulnerabilities (INTEL-SA-00141)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_webui_detect.nasl");
  script_mandatory_keys("intel_amt/installed");

  script_tag(name:"summary", value:"Multiple potential security vulnerabilities in Intel Active Management
Technology (AMT) in Intel CSME firmware may allow arbitrary code execution, a partial denial of service or
information disclosure.");

  script_tag(name:"insight", value:"Intel Active Management Technology is prone to multiple vulnerabilities:

  - Bleichenbacher-style side channel vulnerability in TLS implementation may allow an unauthenticated user to
potentially obtain the TLS session key via the network. (CVE-2018-3616)

  - Multiple buffer overflows may allow a privileged user to potentially execute arbitrary code with Intel AMT
execution privilege via local access. (CVE-2018-3657)

  - Multiple memory leaks may allow an unauthenticated user to potentially cause a partial denial of service via
network access. (CVE-2018-3658)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Intel Active Management Technology before 12.0.5.");

  script_tag(name:"solution", value:"Upgrade to appropriate Intel CSME firmware version.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00141.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "12.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
