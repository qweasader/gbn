# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108206");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-15 09:04:14 +0200 (Tue, 15 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-09 20:45:00 +0000 (Wed, 09 Feb 2022)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2017-9380", "CVE-2017-12064", "CVE-2017-1000240");

  script_name("OpenEMR <= 5.0.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple
vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to:

  - bypass intended access restrictions via a crafted name

  - upload files of dangerous types as a low-privilege user which can result in arbitrary code execution within the
context of the vulnerable application.

  - inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"OpenEMR 5.0.0 and prior");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Apply the patch in the reverenced commit URL.");

  script_xref(name:"URL", value:"https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2017-002");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/commit/b8963a5ca483211ed8de71f18227a0e66a2582ad");
  script_xref(name:"URL", value:"https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2017-001");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_less_equal(version: vers, test_version: "5.0.0")) {
   report = report_fixed_ver(installed_version: vers, fixed_version: "Apply patch");
   security_message(data: report, port: port);
   exit(0);
}
exit(99);
