# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:banu:tinyproxy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124619");
  script_version("2024-03-15T15:36:48+0000");
  script_tag(name:"last_modification", value:"2024-03-15 15:36:48 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-11 11:31:40 +0700 (Mon, 11 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-21 19:44:32 +0000 (Wed, 21 Sep 2022)");

  script_cve_id("CVE-2022-40468");

  # nb: No (major) Linux distribution is covering this currently via backports
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Tinyproxy <= 1.11.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_tinyproxy_http_detect.nasl");
  script_mandatory_keys("tinyproxy/detected");

  script_tag(name:"summary", value:"Tinyproxy is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Potential leak of left-over heap data if custom error page
  templates containing special non-standard variables are used.");

  script_tag(name:"affected", value:"Tinyproxy version 1.11.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Notes:

  - The latest available stable release 1.11.1 has been released in 2022

  - Fixes are only available in current development branch

  - Please create an override for this result if the target software has been build from this
  development branch");

  script_xref(name:"URL", value:"https://github.com/tinyproxy/tinyproxy/issues/457#issuecomment-1264176815");
  script_xref(name:"URL", value:"https://github.com/tinyproxy/tinyproxy/commit/3764b8551463b900b5b4e3ec0cd9bb9182191cb7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
