# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:puppet:enterprise";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106930");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-06 15:23:17 +0700 (Thu, 06 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-24 16:29:00 +0000 (Sat, 24 Feb 2018)");

  script_cve_id("CVE-2017-2296");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Puppet Enterprise 2017 < 2017.2.2 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_puppet_enterprise_detect.nasl");
  script_mandatory_keys("puppet_enterprise/installed");

  script_tag(name:"summary", value:"Puppet Enterprise is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Using specially formatted strings with certain formatting characters as
  Classifier node group names or RBAC role display names causes errors, effectively causing a DOS to the service.");

  script_tag(name:"affected", value:"Puppet Enterprise 2017.1.x and 2017.2.1.");

  script_tag(name:"solution", value:"Update to version 2017.2.2 or later.");

  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2017-2296");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version:"2017.1.0", test_version2: "2017.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2017.2.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
