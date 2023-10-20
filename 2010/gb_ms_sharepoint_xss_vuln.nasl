# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800481");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_cve_id("CVE-2010-0716");
  script_name("Microsoft SharePoint Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.hacktics.com/content/advisories/AdvMS20100222.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/509683/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");
  script_dependencies("remote-detect-WindowsSharepointServices.nasl");
  script_mandatory_keys("MicrosoftSharePointTeamServices/version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to leverage
  same-origin relationships and conduct cross-site scripting attacks by
  uploading TXT files.");

  script_tag(name:"affected", value:"Microsoft Office SharePoint Server 2007 12.0.0.6421 and prior.");

  script_tag(name:"insight", value:"This flaw is due to insufficient validation of user supplied data
  passed into 'SourceUrl' and 'Source' parameters in the 'download.aspx' in
  SharePoint Team Services.");

  script_tag(name:"solution", value:"Upgrade to SharePoint Server 2010 or later.");

  script_tag(name:"summary", value:"Microsoft SharePoint Server is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

stsVer = get_kb_item("MicrosoftSharePointTeamServices/version");
if(isnull(stsVer)){
  exit(0);
}

if(version_in_range(version:stsVer, test_version:"12.0", test_version2:"12.0.0.6421")){
  report = report_fixed_ver(installed_version:stsVer, vulnerable_range:"12.0 - 12.0.0.6421");
  security_message(port: 0, data: report);
}
