# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100049");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6868");
  script_name("Multiple EditeurScripts Products 'msg' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34112");

  script_tag(name:"summary", value:"Multiple EditeurScripts products are prone to a cross-site scripting
  vulnerability because they fail to sufficiently sanitize
  user-supplied data.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks.");
  script_tag(name:"affected", value:"The following products and versions are affected:

  - EScontacts v1.0

  - EsBaseAdmin v2.1

  - EsPartenaires v1.0

  - EsNews v1.2

  Other versions may also be affected.");

  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

dir = make_list( "/EsContacts","/EsBaseAdmin/default","/EsPartenaires","/EsNews/admin/news" );
x = 0;

foreach d( dir ) {

  site = "/login.php";

  if( d == "/EsNews/admin/news" ) {
    site = "/modifier.php";
  }

  url = string( d, site, '?msg=<script>alert(document.cookie);</script>' );
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( buf == NULL ) continue;

  if( buf =~ "^HTTP/1\.[01] 200" && egrep( pattern:"<script>alert\(document\.cookie\);</script>", string:buf ) ) {
    es_soft = eregmatch( string:d, pattern:"/([a-zA-Z]+)/*.*" );
    if( ! isnull( es_soft[1] ) ) {
      vuln_essoft_found[x] = es_soft[1];
    }
  }
  x++;
}

if( vuln_essoft_found ) {
  info = string( "The following vulnerable EditeurScripts products were detected on the remote host:\n\n" );
  foreach found( vuln_essoft_found ) {
    if( ! isnull( found ) ) {
      vuln = TRUE;
      info += string("  ",found,"\n");
    }
  }

  if( vuln ) {
    security_message( port:port, data:info );
    exit( 0 );
  }
}

exit( 99 );
