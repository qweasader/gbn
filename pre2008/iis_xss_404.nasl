# SPDX-FileCopyrightText: 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# admins who installed this patch would necessarily not be vulnerable to CVE-2001-1325

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10936");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Microsoft Internet Information Services (IIS) XSS via 404 error");
  script_cve_id("CVE-2002-0148", "CVE-2002-0150"); # lots of bugs rolled into one patch...
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"IAVA", value:"2002-A-0002");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-018");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4476");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4483");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4486");
  script_xref(name:"URL", value:"http://jscript.dk/adv/TL001/");

  script_tag(name:"summary", value:"This IIS Server appears to vulnerable to one of the cross site scripting
  attacks described in MS02-018.");

  script_tag(name:"insight", value:"The default '404' file returned by IIS uses scripting to output a link to
  top level domain part of the url requested. By crafting a particular URL it is possible to insert arbitrary
  script into the page for execution.

  The presence of this vulnerability also indicates that the host is vulnerable to the other issues identified
  in MS02-018 (various remote buffer overflow and cross site scripting attacks...)");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

# nb: Check makes a request for non-existent HTML file. The server should return a 404 for this request.
# The unpatched server returns a page containing the buggy JavaScript, on a patched server this has been
# updated to further check the input...

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

banner = http_get_remote_headers( port:port );
if( "Microsoft-IIS" >!< banner ) exit( 0 );

req = http_get( item:"/blah.htm", port:port );
r = http_keepalive_send_recv( port:port, data:req );
if( ! r ) exit( 0 );

str1 = "urlresult";
str2 = "+ displayresult +";

if( ( str1 >< r ) && ( str2 >< r ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
