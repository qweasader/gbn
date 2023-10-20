# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:theforeman:foreman';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106418");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-23 02:29:00 +0000 (Fri, 23 Feb 2018)");

  script_cve_id("CVE-2016-6319");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Foreman XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_foreman_detect.nasl");
  script_mandatory_keys("foreman/installed");

  script_tag(name:"summary", value:"Foreman is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Label parameter of all form helpers was not escaped allowing XSS. The
Foreman itself did not contain exploitable code but other plugins that relied on form helpers could be
vulnerable. One known vulnerable plugin is Remote Execution.");

  script_tag(name:"affected", value:"Version 1.6.0 to 1.12.1.");

  script_tag(name:"solution", value:"Upgrade to 1.12.2 or later.");

  script_xref(name:"URL", value:"https://theforeman.org/security.html#2016-6319");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.6.0", test_version2: "1.12.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.12.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
