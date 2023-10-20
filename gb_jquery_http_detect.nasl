# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141622");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-01 09:53:59 +0700 (Thu, 01 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("jQuery Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"Follow redirects", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"HTTP based detection of jQuery.");

  script_tag(name:"insight", value:"Script preference 'Follow redirects':

  This script currently isn't following HTTP redirects (30x) by default. If you would like to enable
  this functionality, please set the related preference to 'yes'.

  Please do note that this functionality currently might cause a reporting of the same jQuery
  installation / location multiple times for specific / special targets. If this is the case for the
  target in question, please disable it again for the time being.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

function resolve_jquery_location(jquerydir, jqueryfile, basedir) {

  local_var jquerydir, jqueryfile, basedir;
  local_var location;

  if (!isnull(jquerydir)) {
    if (jquerydir !~ "^/" && jquerydir !~ "^\./")
      location = basedir + "/" + jquerydir;
    else if (jquerydir =~ "^\./")
      location = ereg_replace(string: jquerydir, pattern: "^(\./)", replace: basedir + "/");
    else if (jquerydir =~ "^/")
      location = jquerydir;
    else
      location = basedir + jquerydir;
  } else {
    location = basedir;
  }

  if (location != "/")
    location = ereg_replace(string: location, pattern: "(/)$", replace: "");

  if (jqueryfile !~ "^/")
    jqueryfile = "/" + jqueryfile;

  if (location == "/")
    return jqueryfile;
  else
    return( location + jqueryfile );
}

pattern = 'src=["\']([^ ]*)(jquery[-.]?([0-9.]+(-rc[0-9])?)?(\\.min|\\.slim|\\.slim\\.min)?\\.js)';
detected_urls = make_list();
detected_vers = make_list();

port = http_get_port(default: 80);

opt = script_get_preference("Follow redirects", id: 1);
if (opt && opt == "yes")
  follow_redirects = TRUE;

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/";
  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "^HTTP/1\.[01] ")
    continue;

  initial_url = "";

  if (follow_redirects && res =~ "^HTTP/1\.[01] 30[0-9]") {
    redirect_loc = http_extract_location_from_redirect(port: port, data: res, current_dir: install);
    redirect_dir = http_extract_location_from_redirect(port: port, data: res, dir_only: TRUE, current_dir: install);
    res = http_get_cache(port: port, item: redirect_loc);
    if (!res || res !~ "^HTTP/1\.[01] ")
      continue;

    # nb: Used later for the "redirected from" reporting
    initial_url = url;
    url = redirect_loc;
    dir = redirect_dir;
  }

  detect = eregmatch(pattern: pattern, string: res);
  if (!detect)
    continue;

  version = "unknown";
  extra   = "";

  # src="js/get_scripts.js.php?scripts%5B%5D=jquery/jquery-2.1.4.min.js
  # src="js/jquery-1.8.2.min.js"
  # src="jquery-1.8.2.min.js"
  # src="/jquery-1.8.2.min.js"
  # src="/jquery-1.12.4.js"
  # src="/pub/jquery-1.11.2.min.js"
  # src="./js/jquery-1.11.2.min.js"
  # src="https://code.jquery.com/jquery-3.2.1.slim.min.js"
  #
  # This is hosted "externally" and the "//" means that the protocol https:// or http:// is chosen
  # depending on which protocol the web page using this link is running on:
  # src="//code.jquery.com/jquery-1.10.2.min.js
  #
  # Uncommon, but seems to be sometimes used: https://forum.greenbone.net/t/false-positive-jquery-1-9-0-xss-vulnerability/1683
  # src="/js/jquery.2.2.1.min.js"
  # src="/scripts/lib/jquery1.11.2.js"
  #
  # Not covered yet:
  # src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"
  if (!isnull(detect[3])) {

    location = resolve_jquery_location(jquerydir: detect[1], jqueryfile: detect[2], basedir: dir);
    if (!location)
      location = "unknown";

    # nb: Those are "externally" hosted and needs to be handled / reported a little bit differently
    if (detect[1] !~ "^https?://" && detect[1] !~ "^//") {
      # nb: If the location is "unknown" we shouldn't check this as we otherwise might miss the
      # reporting for valid ones...
      if (location != "unknown" &&
          in_array(search: location, array: detected_urls, part_match: FALSE))
        continue;

      concUrl  = "- Identified file: " + http_report_vuln_url(port: port, url: location, url_only: TRUE);
    } else {
      location = "Externally hosted";
      extra  = "The jQuery library is hosted on a different server and the used version has been extracted from the referenced URL.";
      concUrl  = "- Identified file: " + detect[0];
    }

    concUrl += '\n- Referenced at:   ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    if (initial_url)
      concUrl += '\n- Redirected from: ' + http_report_vuln_url(port: port, url: initial_url, url_only: TRUE);

    vers = eregmatch(pattern: "([0-9.]+(-rc[0-9])?)", string: detect[3]);
    if (!isnull(vers[1]))
      version = vers[1];

    detected_urls = make_list(detected_urls, location);

    set_kb_item(name: "jquery/detected", value: TRUE);
    set_kb_item(name: "jquery/http/detected", value: TRUE);
    set_kb_item(name: "jquery/http/" + port + "/installs", value: port + "#---#" + location + "#---#" + version + "#---#" + detect[0] + "#---#" + concUrl + "#---#" + extra);
    # nb: For additional reporting in the Vuln-VTs as users often miss to look into the detection
    # report itself and might be confused where the detection is originating from.
    extra_reporting = concUrl;
    if (extra)
      extra_reporting += '\n\nNote: ' + extra;
    set_kb_item(name: "jquery/http/" + port + "/" + location + "/extra_reporting", value: extra_reporting);
  }

  # src="/imports/jquery/dist/jquery.slim.min.js"
  # src="scripts/jquery.min.js"
  # src="jquery.min.js"
  # src="/jquery.min.js"
  # src="/jquery.js"
  # src="/vendor/jquery/dist/jquery.min.js?v=ee993990e91701d6096efd4e9817ec7d"
  # src="./assets/javascript/jquery.min.js?assets_version=411"
  else if (!isnull(detect[2])) {

    concl = detect[0];
    location = resolve_jquery_location(jquerydir: detect[1], jqueryfile: detect[2], basedir: dir);
    if (!location)
      location = "unknown";

    # nb: Hosted on a different server. On such environments we can't query the version by direct
    # access but still want to report the use of jquery without extracting the version.
    #
    # src="https://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js"
    #
    # nb: The following is interpreted by the browser as an URL where the protocol (https or http) is prepended.
    # src="//ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js"
    #
    if (detect[1] !~ "^https?://" && detect[1] !~ "^//") {

      concUrl  = "- Identified file: " + http_report_vuln_url(port: port, url: location, url_only: TRUE);
      concUrl += '\n- Referenced at:   ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      if (initial_url)
        concUrl += '\n- Redirected from: ' + http_report_vuln_url(port: port, url: initial_url, url_only: TRUE);

      req = http_get(port: port, item: location);
      res = http_keepalive_send_recv(port: port, data: req);
      if (res && res =~ "^HTTP/1\.[01] 200") {

        # /*! jQuery v1.9.1 | (c) 2005, 2012 jQuery Foundation, Inc. | jquery.org/license
        # /*! jQuery v2.1.4 | (c) 2005, 2015 jQuery Foundation, Inc. | jquery.org/license */
        # /*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */
        # /*! jQuery v3.0.0-rc1 | (c) jQuery Foundation | jquery.org/license */
        # * jQuery JavaScript Library v1.3.2
        # * jQuery JavaScript Library v3.0.0-rc1
        vers = eregmatch(pattern: "jQuery (JavaScript Library )?v([0-9.]+(-rc[0-9])?)", string: res, icase: FALSE);
        if (!isnull(vers[2])) {
          version = vers[2];
          concl += '\n' + vers[0];
        }

        # Some jQuery files (especially minimized ones) might miss the comment shown above used for
        # the version extraction. In this case we're trying to gather the version from the following:
        # version="3.1.1 -> The "minimized" version
        # version = "1.11.0 -> The "unminimized" version
        # Both have the same text "jQuery requires a window with a document"
        if (version == "unknown" && "jQuery requires a window with a document" >< res) {
          vers = eregmatch(pattern: 'version\\s*=\\s*["\']?([0-9.]+(-rc[0-9])?)', string: res, icase: FALSE);
          if (!isnull(vers[1])) {
            version = vers[1];
            concl += '\n' + vers[0];
          }
        }
      }
    } else {
      extra  = "The jQuery library is hosted on a different server. Because of this it is not possible to gather the ";
      extra += "version by a direct file access. Please manually inspect the version which gets included on this web page.";
      location = "Externally hosted";
      concl = detect[0];
      concUrl  = "- Identified file: " + detect[0];
      concUrl += '\n- Referenced at:   ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      if (initial_url)
        concUrl += '\n- Redirected from: ' + http_report_vuln_url(port: port, url: initial_url, url_only: TRUE);
    }

    # nb: If the location is "unknown" or "Externally hosted" we shouldn't check this as we
    # otherwise might miss the reporting for valid ones...
    if (location != "unknown" &&
        location != "Externally hosted" &&
        in_array(search: location, array: detected_urls, part_match: FALSE))
      continue;

    detected_urls = make_list(detected_urls, location);

    # nb: Some systems are using something like e.g. the following which we currently can't resolve:
    # a/b/../../js/jquery-1.10.2.min.js
    # c/d/../../js/jquery-1.10.2.min.js
    # Temporarily exclude such links for now.
    if ("../" >< location) {
      if (in_array(search: version, array: detected_vers, part_match: FALSE))
        continue;

      detected_vers = make_list(detected_vers, version);
    }

    set_kb_item(name: "jquery/detected", value: TRUE);
    set_kb_item(name: "jquery/http/detected", value: TRUE);
    set_kb_item(name: "jquery/http/" + port + "/installs", value: port + "#---#" + location + "#---#" + version + "#---#" + concl + "#---#" + concUrl + "#---#" + extra);
    # nb: For additional reporting in the Vuln-VTs as users often miss to look into the detection
    # report itself and might be confused where the detection is originating from.
    extra_reporting = concUrl;
    if (extra)
      extra_reporting += '\n\nNote: ' + extra;
    set_kb_item(name: "jquery/http/" + port + "/" + location + "/extra_reporting", value: extra_reporting);
  }
}

exit(0);
