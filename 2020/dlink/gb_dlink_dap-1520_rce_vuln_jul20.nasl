# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/o:d-link:dap-1520_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144347");
  script_version("2023-04-18T10:19:20+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:19:20 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2020-08-04 02:55:09 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 14:56:00 +0000 (Mon, 27 Jul 2020)");

  script_cve_id("CVE-2020-15892");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DAP-1520 < 1.10b04Beta02 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dap_consolidation.nasl");
  script_mandatory_keys("d-link/dap/detected");

  script_tag(name:"summary", value:"D-Link DAP-1520 is prone to a remote code execution
  vulnerability.");

  script_tag(name:"insight", value:"Whenever a user performs a login action from the web interface,
  the request values are being forwarded to the ssi binary. On the login page, the web interface
  restricts the password input field to a fixed length of 15 characters. The problem is that
  validation is being done on the client side, hence it can be bypassed. When an attacker manages to
  intercept the login request (POST based) and tampers with the vulnerable parameter (log_pass), to a
  larger length, the request will be forwarded to the webserver. This results in a stack-based buffer
  overflow. A few other POST variables, (transferred as part of the login request) are also
  vulnerable: html_response_page and log_user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"D-Link DAP-1520 version 1.10B04 and prior.");

  script_tag(name:"solution", value:"Update to version 1.10b04Beta02 or later.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10169");
  script_xref(name:"URL", value:"https://research.loginsoft.com/vulnerability/classic-stack-based-buffer-overflow-in-dlink-firmware-dap-1520/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.10b04")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10b04Beta02");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
