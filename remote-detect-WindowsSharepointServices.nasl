# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101018");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-04-01 22:29:14 +0200 (Wed, 01 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Windows SharePoint Services (WSS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Microsoft Windows SharePoint Services
  (WSS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

# nb: Request a non existent random aspx page to get the full banner.
if( ! banner = http_get_remote_headers( port:port, file:"/vt-test" + rand() + ".aspx" ) )
  exit( 0 );

if( banner !~ "MicrosoftSharePointTeamServices\s*:" )
  exit( 0 );

dotNetServer = eregmatch( pattern:"Server\s*:\s*(Microsoft-)?IIS/([0-9.]+)", string:banner, icase:TRUE );
mstsVersion = eregmatch( pattern:"MicrosoftSharePointTeamServices\s*:\s*([0-9.]+)", string:banner, icase:TRUE );
xPoweredBy = eregmatch( pattern:"X-Powered-By\s*:\s*([a-zA-Z.]+)", string:banner, icase:TRUE );
aspNetVersion = eregmatch( pattern:"X-AspNet-Version\s*:\s*([0-9.]+)", string:banner, icase:TRUE );

if( mstsVersion ) {

  # TODO: extract the service pack using the [0-9] pattern (minor version number)
  # source: http://www.microsoft.com/downloads/details.aspx?FamilyId=D51730B5-48FC-4CA2-B454-8DC2CAF93951&displaylang=en#Requirements
  wssVersion = "";

  set_kb_item( name:"WindowsSharePointServices/installed", value:TRUE );
  set_kb_item( name:"MicrosoftSharePointTeamServices/version", value:mstsVersion[1] );

  register_host_detail( name:"App", value:"cpe:/a:microsoft:sharepoint_team_services:2007" );

  if( eregmatch( pattern:"(6.0.2.[0-9]+)", string:mstsVersion[1], icase:TRUE ) ) {
    wssVersion = "2.0";
    set_kb_item( name:"WindowsSharePointServices/version", value:wssVersion );

    register_and_report_cpe( app:"Microsoft Windows SharePoint Services (WSS)", ver:wssVersion, base:"cpe:/a:microsoft:sharepoint_services:", expr:"^([0-9]\.[0-9])", regPort:port, insloc:"/" );
  }

  if( eregmatch( pattern:"(12.[0-9.]+)", string:mstsVersion[1], icase:TRUE ) ) {
    wssVersion = "3.0";
    set_kb_item( name:"WindowsSharePointServices/version", value:wssVersion );

    register_and_report_cpe( app:"Microsoft Windows SharePoint Services (WSS)", ver:wssVersion, base:"cpe:/a:microsoft:sharepoint_services:", expr:"^([0-9]\.[0-9])", regPort:port, insloc:"/" );
  }

  report = 'Detected:\n - ' + mstsVersion[0];
  if( wssVersion )
    report += '\n' + "- Microsoft Windows SharePoint Services (WSS): " + wssVersion;
}

if( dotNetServer ) {

  # OS fingerprint using IIS signature
  # https://en.wikipedia.org/wiki/Internet_Information_Services#History
  osVersion = '';
  if( dotNetServer[2] == "10.0" )
    osVersion = "Windows Server 2016 / Windows 10";

  if( dotNetServer[2] == "8.5" )
    osVersion = "Windows Server 2012 R2 / Windows 8.1";

  if( dotNetServer[2] == "8.0" )
    osVersion = "Windows Server 2012 / Windows 8";

  if( dotNetServer[2] == "7.5" )
    osVersion = "Windows Server 2008 R2 / Windows 7";

  if( dotNetServer[2] == "7.0" )
    osVersion = "Windows Server 2008 / Windows Vista";

  if( dotNetServer[2] == "6.0" )
    osVersion = "Windows Server 2003 / Windows XP Professional x64";

  if( dotNetServer[2] == "5.1" )
    osVersion = "Windows XP Professional";

  if( dotNetServer[2] == "5.0" )
    osVersion = "Windows 2000";

  if( dotNetServer[2] == "4.0" )
    osVersion = "Windows NT 4.0 Option Pack";

  if( dotNetServer[2] == "3.0" )
    osVersion = "Windows NT 4.0 SP2";

  if( dotNetServer[2] == "2.0" )
    osVersion = "Windows NT 4.0";

  if( dotNetServer[2] == "1.0" )
    osVersion = "Windows NT 3.51";

  report += '\n - ' + dotNetServer[0];
  if( osVersion )
    report += '\n - Operating System Type: ' + osVersion;
}

if( aspNetVersion ) {
  set_kb_item( name:"aspNetVersion/version", value:aspNetVersion[1] );
  report += '\n - ' + aspNetVersion[0];

  if( xPoweredBy ) {
    set_kb_item( name:"ASPX/enabled", value:TRUE );
    report += '\n - ' + xPoweredBy[0];
  }
}

if( strlen( report ) > 0 )
  log_message( port:port, data:report );

exit( 0 );
