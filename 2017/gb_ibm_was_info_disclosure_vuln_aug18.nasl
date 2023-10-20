# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811499");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-1504");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-08-07 09:51:45 +0530 (Mon, 07 Aug 2017)");
  ## Interim Fix Available. Also if certain feature is used then only vulnerable.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("IBM Websphere Application Server Information Disclosure Vulnerability Aug17");

  script_tag(name:"summary", value:"IBM Websphere application server is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a new feature using the
  PasswordUtil command to enable AES password encryption. If you used this feature,
  then you have a potential for weaker than expected security since some passwords
  did not get encrypted as you might have expected.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to get sensitive information.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  Version 9.0.0.4");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application Server
  (WAS) 9.0.0.5 or later or apply Interim Fix PI82602.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22006803");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100137");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(wasVer == "9.0.0.4")
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:"9.0.0.5");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);