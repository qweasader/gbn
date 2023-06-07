# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:strategy11:formidable_form_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149652");
  script_version("2023-05-09T09:12:26+0000");
  script_tag(name:"last_modification", value:"2023-05-09 09:12:26 +0000 (Tue, 09 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-05 12:22:41 +0000 (Fri, 05 May 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-24419");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Formidable Forms Builder Plugin < 5.5.7 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/formidable/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Formidable Forms Builder' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This flaw could allow an attacker to force higher privileged
  users to execute unwanted actions under their current authentication.");

  script_tag(name:"affected", value:"WordPress Formidable Forms Builder prior to version 5.5.7.");

  script_tag(name:"solution", value:"Update to version 5.5.7 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/formidable/wordpress-formidable-forms-plugin-5-5-6-cross-site-request-forgery-csrf?_s_id=cve");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
