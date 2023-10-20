# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806683");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-1316");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 03:06:00 +0000 (Tue, 06 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-02-12 11:59:34 +0530 (Fri, 12 Feb 2016)");
  script_name("Cisco Video Communications Server Information Disclosure Vulnerability - Feb16");

  script_tag(name:"summary", value:"Cisco TelePresence Video Communication Server is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a failure to properly
  protect an informational URL that contains aggregated call statistics.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to read and disclose certain sensitive data.");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication
  Server (VCS) version X8.1 through X8.7 when used in conjunction with Jabber
  Guest.");

  script_tag(name:"solution", value:"Update to version X8.8 or later. For details refer to the linked vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCux73362");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82948");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160208-vcs");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_vcs_detect.nasl", "gb_cisco_vcs_ssh_detect.nasl");
  script_mandatory_keys("cisco_vcs/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

##X8.1 through X8.7 are vulnerable
if(version_in_range(version:version, test_version:"8.1", test_version2:"8.7.0"))
{
  report = report_fixed_ver(installed_version:version, fixed_version: "Apply the patch");
  security_message(data:report);
  exit(0);
}
exit(99);
