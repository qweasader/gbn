# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811408");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2016-10366");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 17:07:00 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-07-03 20:18:52 +0530 (Mon, 03 Jul 2017)");
  script_name("Elastic Kibana Cross Site Scripting Vulnerability (Jul 2017)");

  script_tag(name:"summary", value:"Elastic Kibana is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation
  of user's input.");

  script_tag(name:"impact", value:"Successful exploitation will lead an attacker to
  execute arbitrary JavaScript in users' browsers.");

  script_tag(name:"affected", value:"Elastic Kibana version 4.3 prior to 4.6.2");

  script_tag(name:"solution", value:"Update to Elastic Kibana version
  4.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl");
  script_mandatory_keys("elastic/kibana/detected");

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

if(version_in_range(version:kibanaVer, test_version:"4.3", test_version2:"4.6.1"))
{
  report = report_fixed_ver(installed_version:kibanaVer, fixed_version:"4.6.2");
  security_message(data:report, port:kibanaPort);
  exit(0);
}
