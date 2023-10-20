# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teleopit:wfm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106575");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-07 15:18:23 +0700 (Tue, 07 Feb 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Teleopti WFM Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teleopti_wfm_detect.nasl");
  script_mandatory_keys("teleopti_wfm/installed");

  script_tag(name:"summary", value:"Teleopti WFM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Teleopti WFM is prone to multiple vulnerabilities:

  - Server Response Contains Plaintext Username and Password

  - Server Response Contains Password Hashes and Authorization Tokens

  - Improper Data Validation Allowing Unauthenticated Admin User Creation");

  script_tag(name:"affected", value:"Version 7.1.0 and previous versions.");

  script_tag(name:"solution", value:"Check with the vendor which version resolves the vulnerabilities.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Feb/13");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "7.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Check with vendor.");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
