# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112262");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-05-02 09:38:12 +0200 (Wed, 02 May 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2018-10571", "CVE-2018-10572", "CVE-2018-10573");

  script_name("OpenEMR < 5.0.1 Multiple Vulnerabilities - March 2018");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Multiple reflected cross-site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary web script or HTML via varios parameters. (CVE-2018-10571)

  Exploiting an issue interface/patient_file/letter.php allows remote authenticated users to bypass intended access restrictions via the newtemplatename and form_body parameters. (CVE-2018-10572)

  Exploiting an issue in interface/fax/fax_dispatch.php allows remote authenticated users to bypass intended access restrictions via the scan parameter. (CVE-2018-10573)");

  script_tag(name:"affected", value:"OpenEMR 5.0.0 and prior");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update OpenEMR to version 5.0.1 or later.");

  script_xref(name:"URL", value:"https://www.open-emr.org/wiki/index.php/Release_Features#Version_5.0.1");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/pull/1519");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/issues/1518");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/commit/699e3c2ef68545357cac714505df1419b8bf2051");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!vers = get_app_version(cpe: CPE, port: port)) exit(0);

if(version_is_less_equal(version: vers, test_version: "5.0.0")) {
   report = report_fixed_ver(installed_version: vers, fixed_version: "5.0.1");
   security_message(data: report, port: port);
   exit(0);
}

exit(0);
