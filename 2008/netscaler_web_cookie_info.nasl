# SPDX-FileCopyrightText: 2008 nnposter
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80023");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("NetScaler web management cookie information");
  script_family("Web Servers");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_cve_id("CVE-2007-6193");
  script_xref(name:"OSVDB", value:"44155");
  script_copyright("Copyright (C) 2008 nnposter");
  script_dependencies("netscaler_web_login.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("citrix/netscaler/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/484182/100/0/threaded");

  script_tag(name:"summary", value:"It is possible to extract information about the remote Citrix NetScaler appliance
  obtained from the web management interface's session cookie, including the appliance's main IP address and software version.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("url_func.inc");
include("string_hex_func.inc");

function cookie_extract (cookie,param)
{
  local_var match;
  match=eregmatch(string:cookie,pattern:' '+param+'=([^; \r\n]*)',icase:TRUE);
  if (isnull(match))
    return;
  return match[1];
}

port = get_kb_item("citrix/netscaler/http/port");
if (!port || !get_tcp_port_state(port))
  exit(0);

cookie=get_kb_item("/tmp/http/auth/"+port);
if (!cookie) exit(0);

found="";

nsip=cookie_extract(cookie:cookie,param:"domain");
if (nsip && nsip+"."=~"^([0-9]{1,3}\.){4}$")
    found+='Main IP address  : '+nsip+'\n';

nsversion=urldecode(estr:cookie_extract(cookie:cookie,param:"nsversion"));
if (nsversion)
    {
    replace_kb_item(name:"www/netscaler/"+port+"/version",
                           value:nsversion);
    found+='Software version : '+nsversion+'\n';
    }

if (!found) exit(0);

report = string(
    "It was possible to determine the following information about the\n",
    "Citrix NetScaler appliance by examining the web management cookie :\n",
    "\n",
    found
);
security_message(port:port,data:report);

exit(0);
