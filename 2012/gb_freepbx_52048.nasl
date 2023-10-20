# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103428");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreePBX 'gen_amp_conf.php' Credentials Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52048");
  script_xref(name:"URL", value:"http://www.freepbx.org/forum/freepbx/development/security-gen-amp-conf-php");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-16 16:59:07 +0100 (Thu, 16 Feb 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_freepbx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("freepbx/installed");
  script_tag(name:"solution", value:"Report indicates that this issue has been fixed. Please contact the
vendor for more information.");
  script_tag(name:"summary", value:"FreePBX is prone to an information-disclosure vulnerability that may
expose administrator's credentials.

Successful exploits will allow unauthenticated attackers to obtain
sensitive information that may aid in further attacks.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = 'cpe:/a:freepbx:freepbx';

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/admin/modules/framework/bin/gen_amp_conf.php");

if(http_vuln_check(port:port, url:url,pattern:"ARI_ADMIN_USERNAME",extra_check:make_list("ARI_ADMIN_PASSWORD","AMPENGINE","DIE_FREEPBX_VERBOSE"))) {
  security_message(port:port);
  exit(0);
}

exit(0);

