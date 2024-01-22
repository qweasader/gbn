# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117574");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2021-07-22 12:59:06 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-15 21:15:00 +0000 (Fri, 15 Oct 2021)");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs
  # / to avoid too large diffs.
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-3744",
                "CVE-2015-3035",
                "CVE-2015-3337",
                "CVE-2016-10367",
                "CVE-2017-1000028",
                "CVE-2017-1000029",
                "CVE-2017-14849",
                "CVE-2017-16877",
                "CVE-2017-6190",
                "CVE-2017-9416",
                "CVE-2018-10822",
                "CVE-2018-1271",
                "CVE-2018-16288",
                "CVE-2018-16836",
                "CVE-2018-3714",
                "CVE-2018-3760",
                "CVE-2018-6184",
                "CVE-2019-12314",
                "CVE-2019-14322",
                "CVE-2019-18371",
                "CVE-2019-3799",
                "CVE-2020-23575",
                "CVE-2020-35736",
                "CVE-2020-5405",
                "CVE-2021-23241",
                "CVE-2021-3223",
                "CVE-2021-40960",
                "CVE-2021-41773",
                "CVE-2021-42013",
                "CVE-2021-43495",
                "CVE-2021-43496",
                "CVE-2021-43798",
                "CVE-2022-23854",
                "CVE-2022-24716",
                "CVE-2022-31793",
                "CVE-2023-34259",
                "CVE-2023-6020");

  script_name("Generic HTTP Directory Traversal (Web Dirs) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Path_Traversal");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal vulnerabilities on
  each directory of the remote web server.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  access paths and directories that should normally not be accessible by a user. This can result in
  effects ranging from disclosure of confidential information to arbitrary code execution.");

  script_tag(name:"affected", value:"The following products are known to be affected by the pattern
  checked in this VT:

  - CVE-2014-3744: st module for Node.js

  - CVE-2015-3035: TP-LINK devices

  - CVE-2015-3337: Elasticsearch

  - CVE-2016-10367: Opsview Monitor Pro

  - CVE-2017-1000028, CVE-2017-1000029: Oracle GlassFish Server

  - CVE-2017-6190 and CVE-2018-10822: D-Link Routers

  - CVE-2017-14849: Node.js

  - CVE-2017-16877, CVE-2018-6184: ZEIT Next.js

  - CVE-2017-9416: Odoo

  - CVE-2018-1271: Spring MVC

  - CVE-2018-16288: LG SuperSign CMS

  - CVE-2018-16836: Rubedo

  - CVE-2018-3714: node-srv node module

  - CVE-2018-3760: Ruby on Rails

  - CVE-2019-12314: Deltek Maconomy

  - CVE-2019-14322: Pallets Werkzeug

  - CVE-2019-18371: Xiaomi Routers

  - CVE-2019-3799 and CVE-2020-5405: Spring Cloud Config

  - CVE-2020-23575: Kyocera Printer d-COPIA253MF

  - CVE-2020-35736: Gate One

  - CVE-2021-23241: MERCUSYS Mercury X18G

  - CVE-2021-3223: Node RED Dashboard

  - CVE-2021-40960: Galera WebTemplate

  - CVE-2021-41773 and CVE-2021-42013: Apache HTTP Server

  - CVE-2021-43495: AlquistManager

  - CVE-2021-43496: Clustering

  - CVE-2021-43798: Grafana v8.x

  - CVE-2022-23854: Schneider Electric Wonderware / AVEVA InTouch Access Anywhere (Secure Gateway)
  and AVEVA Plant SCADA Access Anywhere

  - CVE-2022-24716: Icinga Web 2

  - CVE-2022-31793: Arris routers (e.g. NVG589 and NVG510)

  - CVE-2023-34259: Kyocera Printer TASKalfa 4053ci (bypass for CVE-2020-23575)

  - CVE-2023-6020: Ray Framework

  - No CVE: Huawei HG255s

  - No CVE: Unknown Huawei devices having a '/umweb' endpoint

  Other products might be affected as well.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP requests to previously spidered
  directories of the remote web server and checks the responses.

  Note: Due to the long expected run time of this VT it is currently not enabled / running by
  default. Please set the 'Enable generic web application scanning' setting within the VT
  'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'yes' if you want to run this
  script.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  script_timeout(900);

  exit(0);
}

# nb: We also don't want to run if optimize_test is set to "no"
if( get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

depth = get_kb_item( "global_settings/dir_traversal_depth" );
# nb: "" was added here to catch the (normally quite unlikely) case that the file is accessible
# via e.g. http://example.com/foo/etc/passwd
traversals = traversal_pattern( extra_pattern_list:make_list( "" ), depth:depth );
files = traversal_files();
count = 0;
max_count = 3;
suffixes = make_list(
  "",
  "/", # Oracle GlassFish Server flaw (CVE-2017-1000029) but other environments / technologies might be affected as well
  "%00index.htm", # Kyocera Printer flaws (CVE-2020-23575, CVE-2023-34259) but other environments / technologies might be affected as well
  "%23vt/test", # Spring Cloud Config flaw (CVE-2020-5410) but other environments / technologies might be affected as well
  "%00" ); # PHP < 5.3.4 but other environments / technologies might be affected as well

prefixes = make_list(
  "",
  "//////", # See e.g. https://medium.com/appsflyerengineering/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d
  "\\\\\\", # Reverse cases for the one above.
  "file%3a//", # Oracle GlassFish Server flaw (CVE-2017-1000029) but other environments / technologies might be affected as well
  "c:" ); # Pallets Werkzeug (/base_import/static/c:/windows/win.ini, CVE-2019-14322) but other environments / technologies might be affected as well

port = http_get_port( default:80 );

# nb: If adding dirs here also add them to the related DDI_Directory_Scanner entries
# which have a prepended reference to this VT.
dirs = make_list_unique(
  # MERCUSYS Mercury X18G
  "/loginLess",
  # Gate One
  "/downloads",
  # st module for Node.js
  "/public",
  # Node.js and Spring MVC
  "/static",
  # Spring MVC
  "/spring-mvc-showcase/resources",
  # ZEIT Next.js
  "/_next",
  # LG SuperSign CMS
  "/signEzUI/playlist/edit/upload",
  # node-srv node module
  "/node_modules",
  # Node RED Dashboard
  "/ui_base/js",
  # Elasticsearch
  "/_plugin/head",
  # Oracle GlassFish Server
  "/theme/META-INF",
  "/resource",
  # Rubedo
  "/theme/default/img",
  # Pallets Werkzeug
  "/base_import/static",
  "/web/static",
  "/base/static",
  # Deltek Maconomy
  "/cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS",
  # D-Link Routers
  "/uir",
  # Galera WebTemplate (nb: folder from the PoC looks like a specific dir on a specific setup so
  # so a few different ones are checked)
  "/GallerySite/filesrc/fotoilan/388/middle/",
  "/GallerySite/filesrc/",
  "/GallerySite/",
  # Apache HTTP Server
  "/cgi-bin",
  # Ruby on Rails
  "/assets/file:",
  # Huawei HG255s, see https://cxsecurity.com/issue/WLB-2017090053
  "/css",
  # Kyocera Printer d-COPIA253MF and TASKalfa 4053ci
  "/wlmeng",
  "/wlmdeu",
  # AlquistManager
  "/asd",
  # Clustering
  "/img",
  # Grafana
  "/public/plugins/alertlist",
  # Xiaomi Routers
  "/api-third-party/download/extdisks",
  # Opsview Monitor Pro
  "/monitoring",
  # From https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/nginx-merge-slashes-path-traversal.json
  "/static",
  # TP-Link
  "/login",
  # Schneider Electric Wonderware / AVEVA InTouch Access Anywhere (Secure Gateway)
  "/AccessAnywhere",
  # AVEVA Plant SCADA Access Anywhere
  "/PlantSCADAAccessAnywhere",
  # Odoo
  "/base_import/static",
  # Icinga Web 2
  "/icingaweb2/lib/icinga/icinga-php-thirdparty",
  "/icinga/lib/icinga/icinga-php-thirdparty",
  "/icinga2/lib/icinga/icinga-php-thirdparty",
  "/icinga-web/lib/icinga/icinga-php-thirdparty",
  "/lib/icinga/icinga-php-thirdparty",
  # Huawei Auth-Http Server / devices from:
  # - https://github.com/Vme18000yuan/FreePOC/blob/master/poc/pocsuite/huawei-auth-http-readfile.py
  # - https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/huawei/huawei-firewall-lfi.yaml
  "/umweb",
  # Ray Framework from https://huntr.com/bounties/83dd8619-6dc3-4c98-8f1b-e620fedcd1f6/
  "/static/js",
  # nb: No need to add these three to the dir scanner as these seems to be random dirs:
  "/test/pathtraversal/master", # Spring Cloud Config
  "/a/b/", # Spring Cloud Config
  "a/", # Arris routers
  http_cgi_dirs( port:port ) );

foreach dir( dirs ) {

  if( dir == "/" )
    continue; # nb: Already checked in 2017/gb_generic_http_web_root_dir_trav.nasl

  dir_vuln = FALSE; # nb: Used later to only report each dir only once
  foreach traversal( traversals ) {
    foreach pattern( keys( files ) ) {
      file = files[pattern];
      foreach suffix( suffixes ) {
        foreach prefix( prefixes ) {
          url = dir + "/" + prefix + traversal + file + suffix;
          req = http_get( port:port, item:url );
          res = http_keepalive_send_recv( port:port, data:req );
          if( egrep( pattern:pattern, string:res, icase:TRUE ) ) {
            count++;
            dir_vuln = TRUE;
            vuln += http_report_vuln_url( port:port, url:url ) + '\n\n';
            vuln += 'Request:\n' + chomp( req ) + '\n\nResponse:\n' + chomp( res ) + '\n\n\n';
            break; # Don't report multiple vulnerable pattern / suffixes / prefixes for the very same dir
          }
        }
        if( count >= max_count || dir_vuln )
          break; # nb: No need to continue with that much findings or with multiple vulnerable pattern / suffixes / prefixes for the very same dir
      }
      if( count >= max_count || dir_vuln )
        break;
    }
    if( count >= max_count || dir_vuln )
      break;
  }

  if( count >= max_count )
    break;
}

if( vuln ) {
  report = 'The following affected URL(s) were found (limited to ' + max_count + ' results):\n\n' + chomp( vuln );
  security_message( port:port, data:report );
}

exit( 0 );
