# SPDX-FileCopyrightText: 2008 nnposter
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80022");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("NetScaler web management cookie cipher weakness");

  script_family("Web application abuses");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_cve_id("CVE-2007-6192");
  script_copyright("Copyright (C) 2008 nnposter");
  script_dependencies("netscaler_web_login.nasl", "logins.nasl");
  script_mandatory_keys("citrix/netscaler/http/detected");
  script_require_keys("http/password");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Do not stay logged into the NetScaler web management interface while
browsing other web sites.");

  script_tag(name:"summary", value:"The remote web server is prone to an information disclosure attack.

Description :

The version of the Citrix NetScaler web management interface on the
remote host uses weak encryption for protecting the HTTP cookie
content by XORing sensitive values, including the username and
password, with a fixed key stream.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/484182/100/0/threaded");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("misc_func.inc");
include("url_func.inc");
include("string_hex_func.inc");

function cookie_decode (cookie,param)
{
local_var match;
match=eregmatch(string:cookie,pattern:' '+param+'=([^; \r\n]*)',icase:TRUE);
if (isnull(match)) return NULL;
return base64_decode(str:urldecode(estr:match[1])-'\n');
}


function str_xor ()
{
local_var nargs,result,len,arg1,arg2,i,j;
nargs=max_index(_FCT_ANON_ARGS);
if (nargs==0) return NULL;
result=_FCT_ANON_ARGS[0];
len=strlen(result);
for (i=1; i<nargs; ++i)
    {
    arg1=result;
    arg2=_FCT_ANON_ARGS[i];
    if (len!=strlen(arg2)) return NULL;
    result="";
    for (j=0; j<len; ++j) result+=raw_string(ord(arg1[j])^ord(arg2[j]));
    }
return result;
}


function strleft ()
{
return substr(_FCT_ANON_ARGS[0],0,_FCT_ANON_ARGS[1]-1);
}


port = get_kb_item("citrix/netscaler/http/port");

cookie=get_kb_item("/tmp/http/auth/"+port);
if (!cookie) exit(0);

hostname=get_host_name();
if (!hostname) hostname=get_host_ip();
keystream=str_xor(hostname,cookie_decode(cookie:cookie,param:"ns3"));
if (!keystream || strlen(keystream)==0) exit(0);

ns2=cookie_decode(cookie:cookie,param:"ns2");
ns2len=strlen(ns2);
keylen=strlen(keystream);
if (ns2len<keylen) len=ns2len;
else len=keylen;
guess=str_xor(strleft(ns2,len),strleft(keystream,len));
if (!guess || strlen(guess)==0) exit(0);
if (strleft(get_kb_item("http/password"),len)!=guess) exit(0);

report = string(
    "Sensitive values, including the username and password, can be\n",
    "decrypted by XORing the plaintext with the following fixed key\n",
    "stream :\n",
    "\n",
    hexstr(keystream), "..."
);
security_message(port:port,data:report);

exit(0);
