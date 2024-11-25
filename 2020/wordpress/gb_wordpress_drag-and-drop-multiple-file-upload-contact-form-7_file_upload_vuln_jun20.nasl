# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112764");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-06-10 08:35:00 +0000 (Wed, 10 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-11 00:36:00 +0000 (Thu, 11 Jun 2020)");

  script_cve_id("CVE-2020-12800");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Drag and Drop Multiple File Upload Plugin < 1.3.3.3 Unrestricted File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/drag-and-drop-multiple-file-upload-contact-form-7/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Drag and Drop Multiple File Upload' is
  prone to an unrestricted file upload vulnerability that can result in remote code execution
  (RCE).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The allowed file extension list can be bypassed by appending a %,
  allowing for php shells to be uploaded. No authentication is required for exploitation.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to upload files containing
  malicious php code which then can be executed remotely.");

  script_tag(name:"affected", value:"WordPress Drag and Drop Multiple File Upload plugin before version 1.3.3.3.");

  script_tag(name:"solution", value:"Update the plugin to version 1.3.3.3 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/157951/WordPress-Drag-And-Drop-Multi-File-Uploader-Remote-Code-Execution.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/drag-and-drop-multiple-file-upload-contact-form-7/#developers");

  exit(0);
}

CPE = "cpe:/a:codedropz:drag_and_drop_multiple_file_upload_-_contact_form_7";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version: vers, test_version: "1.3.3.3" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.3.3", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
