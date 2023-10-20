# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800968");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-3830");
  script_name("Microsoft SharePoint Team Services Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/976829");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36817");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53955");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/507419/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("remote-detect-WindowsSharepointServices.nasl");
  script_mandatory_keys("MicrosoftSharePointTeamServices/version");

  script_tag(name:"impact", value:"Attackers can exploit this issue via specially-crafted HTTP requests
  to obtain the source code of arbitrary ASP.NET files from the backend database.");

  script_tag(name:"affected", value:"Microsoft Office SharePoint Server 2007 12.0.0.6219 and prior.");

  script_tag(name:"insight", value:"This flaw is due to insufficient validation of user supplied data
  passed into 'SourceUrl' and 'Source' parameters in the download.aspx in SharePoint Team Services.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft SharePoint Server is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

stsVer = get_kb_item("MicrosoftSharePointTeamServices/version");
if(isnull(stsVer)){
  exit(0);
}

if(version_in_range(version:stsVer, test_version:"12.0", test_version2:"12.0.0.6219")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
