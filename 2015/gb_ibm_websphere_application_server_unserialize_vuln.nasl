# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806624");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-11-17 17:28:17 +0530 (Tue, 17 Nov 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 17:02:03 +0000 (Wed, 24 Jul 2024)");

  script_cve_id("CVE-2015-7450");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("IBM WebSphere Application Server <= 8.5.5.7 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to presence of a deserialization error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code on the affected system.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 8.5.5.7 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#websphere");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "8.5.5.7")){
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
