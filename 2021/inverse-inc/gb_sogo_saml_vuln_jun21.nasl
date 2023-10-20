# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:alinto:sogo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146089");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-06-07 06:40:39 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 03:15:00 +0000 (Fri, 11 Jun 2021)");

  script_cve_id("CVE-2021-28091", "CVE-2021-33054");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SOGo < 2.4.1, 3.x < 5.1.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sogo_http_detect.nasl");
  script_mandatory_keys("sogo/detected");

  script_tag(name:"summary", value:"SOGo is prone to multiple vulnerabilities in SAML.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-28091: Lasso is prone to an improper verification of a cryptographic signature.

  - CVE-2021-33054: SOGo does not validate the signatures of any SAML assertions it receives. Any
    actor with network access to the deployment could impersonate users when SAML is the
    authentication method.");

  script_tag(name:"affected", value:"SOGo prior to version 2.4.1 and 3.x through 5.1.0.");

  script_tag(name:"solution", value:"Update to version 2.4.1, 5.1.1 or later.

  Note: You need to additionally update the Lasso library to version 2.7.0 or later.");

  script_xref(name:"URL", value:"https://www.sogo.nu/news/2021/saml-vulnerability.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.1");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0", test_version2: "5.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
