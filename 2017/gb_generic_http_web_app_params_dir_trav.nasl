# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113002");
  script_version("2022-10-21T10:20:04+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-10-21 10:20:04 +0000 (Fri, 21 Oct 2022)");
  script_tag(name:"creation_date", value:"2017-09-26 10:00:00 +0200 (Tue, 26 Sep 2017)");

  # nb: This has a CVSSv2 score of 5.0 but we want to use a higher value similar to the other
  # gb_generic_http_web* VTs for various reasons.
  script_cve_id("CVE-2019-7254");

  script_name("Generic HTTP Directory Traversal (Web Application URL Parameter) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Path_Traversal");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal vulnerabilities
  within URL parameters of the remote web application.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  access paths and directories that should normally not be accessible by a user. This can result in
  effects ranging from disclosure of confidential information to arbitrary code execution.");

  script_tag(name:"affected", value:"The following products are known to be affected by the pattern
  and URL parameters checked in this VT:

  - CVE-2019-7254: Linear eMerge E3-Series

  Other products might be affected as well.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP requests to previously spidered URL
  parameters (e.g. /index.php?parameter=directory_traversal) of a web application and checks the
  responses.

  Note: Due to the long expected run time of this VT it is currently not enabled / running by
  default. Please set the 'Enable generic web application scanning' setting within the VT
  'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'yes' if you want to run this
  script.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_timeout(900);

  exit(0);
}

# nb: We also don't want to run if optimize_test is set to "no"
if( get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("list_array_func.inc");

depth = get_kb_item( "global_settings/dir_traversal_depth" );
traversals = traversal_pattern( extra_pattern_list:make_list( "/" ), depth:depth );
files = traversal_files();
count = 0;
max_count = 3;
suffixes = make_list(
  "",
  "%23vt/test", # Spring Cloud Config flaw (CVE-2020-5410) but other environments / technologies might be affected as well
  "%00" ); # PHP < 5.3.4 but other environments / technologies might be affected as well

prefixes = make_list(
  "",
  "//////", # See e.g. https://medium.com/appsflyerengineering/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d
  "static//////", # From https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/nginx-merge-slashes-path-traversal.json
  "\\\\\\", # Reverse cases for the ones above.
  "static\\\\\\",
  "c:" ); # Seen for Pallets Werkzeug (CVE-2019-14322) on a specific directory but other environments / technologies might be affected in a similar way so it was also added here

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
cgis = http_get_kb_cgis( port:port, host:host );
if( ! cgis )
  cgis = make_list();

# nb: Syntax of the entries below is described in the http_get_kb_cgis() function description.
cgis = make_list_unique( cgis,
  "/ - c []" ); # CVE-2019-7254 -> /?c=../../../../../../etc/passwd%00

foreach cgi( cgis ) {
  cgiArray = split( cgi, sep:" ", keep:FALSE );
  cgi_vuln = FALSE; # nb: Used later to only report each URL only once
  foreach traversal( traversals ) {
    foreach pattern( keys( files ) ) {
      file = files[pattern];
      foreach suffix( suffixes ) {
        foreach prefix( prefixes ) {
          exp = prefix + traversal + file + suffix;
          urls = http_create_exploit_req( cgiArray:cgiArray, ex:exp );
          foreach url( urls ) {
            req = http_get( port:port, item:url );
            res = http_keepalive_send_recv( port:port, data:req );
            if( egrep( pattern:pattern, string:res, icase:TRUE ) ) {
              count++;
              cgi_vuln = TRUE;
              vuln += http_report_vuln_url( port:port, url:url ) + '\n\n';
              vuln += 'Request:\n' + chomp( req ) + '\n\nResponse:\n' + chomp( res ) + '\n\n\n';
              break; # Don't report multiple vulnerable parameter / pattern / suffixes / prefixes for the very same URL
            }
          }
          if( count >= max_count || cgi_vuln )
            break; # nb: No need to continue with that much findings or with multiple vulnerable parameter / pattern / suffixes / prefixes for the very same URL
        }
        if( count >= max_count || cgi_vuln )
          break;
      }
      if( count >= max_count || cgi_vuln )
        break;
    }
    if( count >= max_count || cgi_vuln )
      break;
  }
  if( count >= max_count )
    break;
}

if( vuln ) {
  report = 'The following affected URL(s) were found (limited to ' + max_count + ' results):\n\n' + chomp( vuln );
  security_message( port:port, data:report );
}

exit( 0 );