###############################################################################
# OpenVAS Vulnerability Test
#
# Novell eDirectory NULL Base DN Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100340");
  script_version("2022-05-17T07:24:43+0000");
  script_tag(name:"last_modification", value:"2022-05-17 07:24:43 +0000 (Tue, 17 May 2022)");
  script_tag(name:"creation_date", value:"2009-11-09 11:17:02 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3862");
  script_name("Novell eDirectory NULL Base DN Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("novell_edirectory_detect.nasl");
  script_mandatory_keys("eDirectory/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36902");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7004721");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-075/");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Novell eDirectory is prone to a denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to cause the server to become
  unresponsive, denying service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to Novell eDirectory 8.8.5 ftf1 and eDirectory 8.7.3.10
  ftf2 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:novell:edirectory", "cpe:/a:netiq:edirectory" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! major = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );
revision = str_replace( string:revision, find:".", replace:"" );

instver = major;

if( sp > 0 )
  instver += ' SP' + sp;

if( major == "8.8" )
{
  if( sp && sp > 0 )
  {
    if( sp == 5 )
    {
      if( revision && revision < 2050100 )
      {
        vuln = TRUE;
      }
    } else
    {
      if( sp < 5 )
      {
        vuln = TRUE;
      }
    }
  } else
  {
    vuln = TRUE;
  }
}
else if( major =~ "^8\.7\.3" )
{
  m = major - "8.7.3";

  if(m =~ "^\.[0-9]+") {
     m -= ".";
  }

  if( strlen( m ) > 0 )
  {
    m = int(m);

   if( m && m < 10 )
   {
     vuln = TRUE;
   }

   if( m && m == 10 )
   {
     if( ! sp && ! revision )
     {
       vuln = TRUE;
     }
   }

  } else {
      vuln = TRUE;
  }
}
else if( major == "8.8.1" )
{
  vuln = TRUE;
}

else if( major == "8.8.2" )
{
  if( ! revision && ! sp )
  {
    vuln = TRUE;
  }
}

else if( major =~ "^[0-7]\." )
{
  vuln = TRUE;
}

if( vuln )
{
  report = report_fixed_ver( installed_version:instver, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit(0);
}

exit(99);
