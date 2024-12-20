# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:piwigo:piwigo';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106879");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-06-16 15:14:30 +0700 (Fri, 16 Jun 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-19 18:15:00 +0000 (Mon, 19 Jun 2017)");

  script_cve_id("CVE-2017-9463", "CVE-2017-9464");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Piwigo is prone to multiple vulnerabilities:

  - SQL Injection (CVE-2017-9463)

  - Open Redirect (CVE-2017-9464)");

  script_tag(name:"affected", value:"Piwigo version 2.9.0 and prior.");

  script_tag(name:"solution", value:"Update to version 2.9.1 or later.");

  script_xref(name:"URL", value:"https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2017-003");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/705");
  script_xref(name:"URL", value:"https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2017-007");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/706");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
