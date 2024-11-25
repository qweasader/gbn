# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808503");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-4093");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-06-28 18:20:50 +0530 (Tue, 28 Jun 2016)");
  script_name("Elastic Kibana Cross-site scripting (XSS) Vulnerability - Linux");

  script_tag(name:"summary", value:"Elastic Kibana is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to an insufficient
  validation of user supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Elastic Kibana version 4.0.x
  before 4.0.3 on Linux.");

  script_tag(name:"solution", value:"Update to Elastic Kibana version 4.0.3,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75107");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535726/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/kibana/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!kibanaPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!kibanaVer = get_app_version(cpe:CPE, port:kibanaPort)){
 exit(0);
}

if(version_in_range(version:kibanaVer, test_version:"4.0.0", test_version2:"4.0.2"))
{
  report = report_fixed_ver(installed_version:kibanaVer, fixed_version:"4.0.3");
  security_message(data:report, port:kibanaPort);
  exit(0);
}
