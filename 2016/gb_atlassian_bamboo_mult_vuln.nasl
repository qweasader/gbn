# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:bamboo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807266");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2015-8361", "CVE-2014-9757");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:55:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-02-19 10:03:11 +0530 (Fri, 19 Feb 2016)");
  script_name("Atlassian Bamboo Multiple Vulnerabilities (Feb 2016)");

  script_tag(name:"summary", value:"Atlassian Bamboo is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The Ignite Realtime Smack XMPP API does not validate serialized data
    in an XMPP message.

  - The multiple unspecified services do not require authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary java code, and to obtain sensitive information,
  modify settings, or manage build agents.");

  script_tag(name:"affected", value:"Atlassian Bamboo 2.4 through 5.9.9");

  script_tag(name:"solution", value:"Upgrade to version 5.9.9 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/BAM-17102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83104");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83107");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/BAM-17099");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_bamboo_detect.nasl");
  script_mandatory_keys("AtlassianBamboo/Installed");
  script_xref(name:"URL", value:"https://www.atlassian.com/software/bamboo");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!bambooPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!bambooVer = get_app_version(cpe:CPE, port:bambooPort)){
  exit(0);
}

if(version_in_range(version:bambooVer, test_version:"2.4", test_version2:"5.9.8"))
{
  report = report_fixed_ver(installed_version:bambooVer, fixed_version:"5.9.9");
  security_message(data:report, port:bambooPort);
  exit(0);
}
