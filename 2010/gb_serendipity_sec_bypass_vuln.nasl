# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:s9y:serendipity";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801337");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1916");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Serendipity 'Xinha WYSIWYG' Editor Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://www.php-security.org/2010/05/10/mops-2010-020-xinha-wysiwyg-plugin-configuration-injection-vulnerability/index.html");
  script_xref(name:"URL", value:"http://www.php-security.org/2010/05/10/mops-2010-019-serendipity-wysiwyg-editor-plugin-configuration-injection-vulnerability/index.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Serendipity/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass intended access
  restrictions and modify the configuration of arbitrary plugins.");
  script_tag(name:"affected", value:"Serendipity version 1.5.2 and on all platforms.");
  script_tag(name:"insight", value:"The flaw is due to an input validation error in 'Xinha WYSIWYG' editor with
  dynamic configuration feature enabled when processing the,

  - crafted 'backend_config_secret_key_location' and 'backend_config_hash'
     parameters that are used in a SHA1 hash of a shared secret that can be
     known or externally influenced, which are not properly handled by the
     'Deprecated config passing' feature.

  - crafted 'backend_data' and 'backend_data[key_location]' variables, which
     are not properly handled by the 'xinha_read_passed_data()' function.");
  script_tag(name:"solution", value:"Upgrade to Serendipity version 1.5.3 or later.");
  script_tag(name:"summary", value:"Serendipity is prone to a security bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.s9y.org/12.html");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if( ! serPort = get_app_port(cpe:CPE)) exit(0);

if( ! infos = get_app_version_and_location(cpe:CPE, port:serPort, exit_no_version:TRUE)) exit(0);
ver = infos['version'];
dir = infos['location'];

if(!isnull(ver) && (version_is_less_equal(version:ver, test_version:"1.5.2")))
{
  if((dir != NULL))
  {
    sndReq = http_get(item:string(dir, "/htmlarea/examples/ExtendedDemo.html"),
                      port:serPort);
    rcvRes = http_send_recv(port:serPort, data:sndReq);
    if(">Xinha Extended Example<" >< rcvRes){
      security_message(serPort);
    }
  }
}
