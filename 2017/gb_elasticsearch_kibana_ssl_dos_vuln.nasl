# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811406");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8452");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-19 11:57:00 +0000 (Mon, 19 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-07-03 20:01:42 +0530 (Mon, 03 Jul 2017)");
  script_name("Elastic Kibana 'SSL Client Access' DoS Vulnerability");

  script_tag(name:"summary", value:"Elastic Kibana is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to Kibana is configured for SSL
  client access, file descriptors will fail to be cleaned up after certain requests
  and will accumulate over time until the process crashes. Requests that are
  canceled before data is sent can also crash the process.");

  script_tag(name:"impact", value:"Successful exploitation will lead to denial of
  service condition.");

  script_tag(name:"affected", value:"Elastic Kibana version 5.x prior to
  5.2.1.");

  script_tag(name:"solution", value:"Update to Elastic Kibana version
  5.2.1 or later.");

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

if(version_in_range(version:kibanaVer, test_version:"5.0", test_version2:"5.2.0"))
{
  report = report_fixed_ver(installed_version:kibanaVer, fixed_version:"5.2.1");
  security_message(data:report, port:kibanaPort);
  exit(0);
}
