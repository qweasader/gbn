# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sugarcrm:sugarcrm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140399");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-26 13:48:15 +0700 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-1000253");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SugarCRM php-saml Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_detect.nasl");
  script_mandatory_keys("sugarcrm/installed");

  script_tag(name:"summary", value:"SugarCRM is prone to a signature validation vulnerability in php-saml.");

  script_tag(name:"insight", value:"The onelogin/php-saml third party library which ships as part of the
SugarCRM application is  potentially vulnerable to Response Wrapping attacks resulting in a malicious user
gaining unauthorized access to the system. This issue impacts environments where SAML authentication is
configured and enabled supporting EncryptedAssertion.");

  script_tag(name:"affected", value:"SugarCRM version 6.5, 7.7 and 7.8.");

  script_tag(name:"solution", value:"Update to version 6.5.26, 7.7.2.2, 7.8.2.1 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"http://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2017-003/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.5.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5.26");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^7\.7\.") {
  if (version_is_less(version: version, test_version: "7.7.2.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.7.2.2");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^7\.8\.") {
  if (version_is_less(version: version, test_version: "7.8.2.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.8.2.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
