# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

global_var xerox_cookie, xerox_last_user, xerox_last_pass;

# @brief Returns an array containing the URL for a Xerox printer detection
#        as the array key and the regex to extract the type/model as the value.
#
# @note The array key might contain a pattern like e.g. (numbers incrementing
#       for multiple same URLs):
#
#       #--avoid-dup1--#
#
#       to be able to have different array keys for the same URL.
#       Make sure to strip such patterns away with ereg_replace
#       in the VT calling this function.
#
# @return An array as described in the function description.
#
function get_xerox_detect_urls() {

  local_var xerox_detect_urls;

  xerox_detect_urls = make_array();

  # nb: Some uses "<div", some "<tb" for the 'id ="' part below
  xerox_detect_urls["/header.php"]                                            = 'id="productName">XEROX ((WorkCentre|Phaser|ColorQube) [^<]+)</div>';      # WorkCentre 6400 a.o.
  xerox_detect_urls["/sitemap.php"]                                           = 'id="productName">XEROX<sup>&reg; </sup>([^<]+)<sup>[^<]+</sup>([^<]+)</'; # WorkCentre 6655 a.o.
  xerox_detect_urls["/hdstat.htm"]                                            = '(WorkCentre [^ \r\n]+)';                                                  # WorkCentre 7120 a.o.
  xerox_detect_urls["/hdstat.htm#--avoid-dup1--#"]                            = '"productName">\\s*Xerox ([^ ]+)';                                           # Xerox D136 Copier-Printer a.o.
  xerox_detect_urls["/headhome.htm"]                                          = '<title>((Xerox )?(WorkCentre|Phaser) [^ <\r\n]+)';                        # WorkCentre 6605dn a.o.
  xerox_detect_urls["/tabsFrame.dhtml"]                                       = '(WorkCentre [^ <]+)';                                                     # WorkCentre M20i a.o.
  xerox_detect_urls["/tabsFrame.dhtml#--avoid-dup1--#"]                       = 'Xerox&nbsp;(Phaser [^<]+)<';                                              # Phaser 4622 a.o.
  xerox_detect_urls["/hdjobq.htm"]                                            = '((WorkCentre|ApeosPort-IV) [^ \r\n]+)';                                   # WorkCentre M118 a.o
  xerox_detect_urls["/home.html"]                                             = '((WorkCentre|Phaser|ColorQube) [^ \n\r<]+)';                              # Phaser 3435 a.o
  xerox_detect_urls["/properties/configuration.php"]                          = 'Machine Model:</td><td>Xerox (AltaLink [^<]+)';                           # AltaLink
  xerox_detect_urls["/setting/prtinfo.htm"]                                   = 'Product Name</td><td class=std_2>(DocuPrint [^<]+)';                      # DocuPrint
  xerox_detect_urls["/isgw/Welcome.do?method=setupStartPage"]                 = '"signatureText1">[A-Za-z ]+?Xerox ([^<]+)';                               # Nuvera, Docuprint a.o.
  xerox_detect_urls["/isgw/Welcome.do?method=setupStartPage#--avoid-dup1--#"] = '"signatureText1">Xerox\xae([^<]+)';                                       # Xerox 700 a.o.
  xerox_detect_urls["/isgw/Welcome.do?method=setupStartPage#--avoid-dup2--#"] = '"signatureText1">Xerox.. ([^<]+)';                                        # Xerox? Versant a.o.
  xerox_detect_urls["/wt4/home"]                                              = '"_blank">Xerox ([^<]+)';                                                  # some Xerox Versant a.o.
  xerox_detect_urls["/home/msg/message_en-US.json"]                           = '("Xerox Asset Tag")';                                                     # some Xerox Phaser a.o.
  xerox_detect_urls["/wt2parser.cgi?home_en"]                                 = '<td align="left" valign="middle" class="name">DC-([0-9]+)[^<]*</td>';     # DocuColor, e.g. DC-260-D44DB8
  xerox_detect_urls["/sprt.htm"]                                              = "var prd='(DocuColor [0-9]+)";                                             # DocuColor, e.g. DocuColor 1450 GA

  # Detection string from dont_print_on_printers.nasl. TBD: Include here?
  # if( banner && "Server: Xerox_MicroServer/Xerox" >< banner || "Server: EWS-NIC" >< banner || "<title>DocuPrint" >< banner || "<title>Phaser" >< banner || ( "XEROX WORKCENTRE" >< banner && "Xerox Corporation. All Rights Reserved." >< banner ) || ( "DocuCentre" >< banner && "Fuji Xerox Co., Ltd." >< banner ) ) {

  return xerox_detect_urls;
}

function xerox_default_logins() {

  return make_list("admin:1111",
                   "11111:x-admin",
                   "admin:x-admin",
                   "admin:sysadmin",
                   "admin:admin",
                   "Administrator:administ",
                   "Administrator:Fiery.1",
                   "admin:2222",
                   "HTTP:admin",
                   "savelogs:crash");
}

function check_xerox_default_login( model, port ) {

  local_var model, port;
  local_var xerox, logins, host, useragent, _login, user_pass, username;
  local_var password, login_data, len, req, buf, userpass64, c_buf;

  xerox = xerox_login_details(model:model, port:port);
  if(!xerox) return FALSE;

  logins = xerox_default_logins();

  host = http_host_name(port:port);
  useragent = http_get_user_agent();

  foreach _login(logins) {

    user_pass = split(_login, sep:":", keep:FALSE);
    username = user_pass[0];
    password = user_pass[1];

    login_data = xerox['login_data'];
    if(login_data) {
      login_data = str_replace(string:login_data, find:"%%%USERNAME%%%", replace:username);
      login_data = str_replace(string:login_data, find:"%%%PASSWORD%%%", replace:password);
    }

    len = strlen(login_data);

    if(xerox['req_type'] == "POST") {

      if(xerox['login_url_success']) {
        req = string(xerox['req_type_success'], " ", xerox['login_url_success'], " HTTP/1.1\r\n",
                     "Host: ", host, "\r\n",
                     "User-Agent: ", useragent, "\r\n\r\n");

        buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
        xerox_error_exit(buf:buf);

        if(eregmatch(pattern:xerox['login_success'], string:buf)) {
          return 2; # setup without auth
        }
      }

      req = string("POST ", xerox['login_url'], " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: ", useragent, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", len, "\r\n");

      if(xerox_cookie) req += string("Cookie: ", xerox_cookie, "\r\n");

      req += string("\r\n",login_data,"\r\n");
    }

    else if(xerox['req_type'] == "GET") {

      if(xerox['req_auth'] == "BASIC") {

        userpass = username + ':' + password;
        userpass64 = base64(str:userpass);

        req = string("GET ", xerox['login_url'], " HTTP/1.1\r\n",
                     "Host: ", host, "\r\n");

        c_buf = http_keepalive_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);
        xerox_error_exit(buf:c_buf);

        if("HTTP/1.1 401" >!< c_buf && "HTTP/1.1 302" >!< c_buf) return 2; # setup without auth

        if(xerox_cookie) req += string("Cookie: ", xerox_cookie, "\r\n");

        req += string("Authorization: Basic ", userpass64, "\r\n\r\n");

      }
    } else {
      return FALSE;
    }

    buf = http_send_recv(port:port, data:req, bodyonly:FALSE); # login

    if(xerox['http_status'] >< buf) {

      if(xerox['login_url_success']) {
        req = string(xerox['req_type_success'], " ", xerox['login_url_success'], " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n");

        if(xerox_cookie) req += string("Cookie: ", xerox_cookie, "\r\n");

        req += string("User-Agent: ", useragent, "\r\n\r\n");

        buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
        xerox_error_exit(buf:buf);
      }

      if(eregmatch(pattern:xerox['login_success'], string:buf)) {
        xerox_last_user = username;
        xerox_last_pass = password;
        return 1;
      }
    }
  }
  return FALSE;
}

function xerox_login_details( model, port ) {

  local_var model, port;

  xerox = make_array();

  if(model == "WorkCentre 5030"   ||
     model == "WorkCentre 5135"   ||
     model == "WorkCentre 5150"   ||
     model == "WorkCentre 5632"   ||
     model == "WorkCentre 5638"   ||
     model == "WorkCentre 5655"   ||
     model == "WorkCentre 5745"   ||
     model == "WorkCentre 5755"   ||
     model == "WorkCentre 5765"   ||
     model == "WorkCentre 5775"   ||
     model == "WorkCentre 6400S"  ||
     model == "WorkCentre 6400X"  ||
     model == "WorkCentre 6400XF" ||
     model == "WorkCentre 7525"   ||
     model == "WorkCentre 7530"   ||
     model == "WorkCentre 7535"   ||
     model == "WorkCentre 7545"   ||
     model == "WorkCentre 7556"   ||
     model == "WorkCentre 7765"   ||
     model == "ColorQube 9301"    ||
     model == "ColorQube 9302"    ||
     model == "ColorQube 9303"    ||
     model == "Phaser 6700DT") {

    if(!xeorx_cookie) xerox_set_cookie( url:"/header.php", port:port );

    xerox['req_type'] = "POST";
    xerox['login_url'] = '/userpost/xerox.set';
    xerox['login_data'] = '_fun_function=HTTP_Authenticate_fn&NextPage=%2Fproperties%2Fauthentication%2FluidLogin.php&webUsername=%%%USERNAME%%%&webPassword=%%%PASSWORD%%%&frmaltDomain=default';

    xerox['req_type_success'] = "GET";
    xerox['login_url_success'] = '/header.php';

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = '>Logout</a>';

    return xerox;
  }

  else if(model == "WorkCentre 5225"    ||
          model == "WorkCentre 5225A"   ||
          model == "WorkCentre 5325"    ||
          model == "WorkCentre 7120"    ||
          model == "WorkCentre 7232"    ||
          model == "WorkCentre 7328"    ||
          model == "WorkCentre 7345"    ||
          model == "WorkCentre 7346"    ||
          model == "WorkCentre 7425"    ||
          model == "WorkCentre 7428"    ||
          model == "ApeosPort-IV C3370" ||
          model == "ApeosPort-IV C4470" ||
          model == "WorkCentre 7435") {

    xerox['req_type'] = "GET";
    xerox['login_url'] = '/prscauthconf.htm';
    xerox['req_auth'] = "BASIC";

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = 'HTTP/1.1 200';

    return xerox;
  }

  else if(model == "WorkCentre 6505DN" ||
          model == "Phaser 6128MFP-N") {

    xerox['req_type'] = "GET";
    xerox['login_url'] = '/srvcset/emlusrlst.htm';
    xerox['req_auth'] = "BASIC";

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = '>Email Address Book';

    return xerox;
  }

  else if(model == "WorkCentre M20i"  ||
          model == "WorkCentre PE120" ||
          model == "WorkCentre 4118"  ||
          model == "WorkCentre 4150"  ||
          model == "WorkCentre 4250") {

    xerox['req_type'] = "GET";
    xerox['login_url'] = '/reloadMaintenance.dhtml';
    xerox['req_auth'] = "BASIC";

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = 'this.location = "(/maintenance/index.dhtml|/properties/maintenance/fwupgrade.dhtml)"';

    return xerox;
  }

  else if (model == "WorkCentre 7132" ||
           model == "WorkCentre 7235" ||
           model == "WorkCentre 7242" ||
           model == "WorkCentre 7245") {

    xerox['req_type'] = "GET";
    xerox['login_url'] = '/spadm.htm';
    xerox['req_auth'] = "BASIC";

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = '<TITLE>Internet Services Settings';

    return xerox;
  }

  else if (model == "generic_basic_auth") {

    xerox['req_type'] = "GET";
    xerox['login_url'] = '/';
    xerox['req_auth'] = "BASIC";

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = 'HTTP/1.1 200';

    return xerox;
  }

  else if (model == "WORKCENTRE PRO") {

    xerox['req_type'] = "GET";
    xerox['login_url'] = '/properties/upgrade/m_software.dhtml';
    xerox['req_auth'] = "BASIC";

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = 'HTTP/1.1 200';

    return xerox;
  }

  else if (model == "WorkCentre 3210" ||
           model == "WorkCentre 3220" ||
           model == "WorkCentre 3550" ||
           model == "Phaser 3435") {

    xerox['req_type'] = "GET";
    xerox['login_url'] = '/properties/securitysettings.html';
    xerox['req_auth'] = "BASIC";

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = '<title> Security Settings';

    return xerox;
  }

  else if (model == "ColorQube 8570") {

    xerox['req_type'] = "GET";
    xerox['login_url'] = '/securitysettings.html';
    xerox['req_auth'] = "BASIC";

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = 'Administrative Security Settings';

    return xerox;
  }

  else if(model == "Phaser 7760"   ||
          model == "Phaser 7760DN" ||
          model == "Phaser 7760GX") {

    xerox['req_type'] = "GET";
    xerox['login_url'] = '/deletesecurejobs.html';
    xerox['req_auth'] = "BASIC";

    xerox['http_status'] = 'HTTP/1.1 200';
    xerox['login_success'] = '<b>Delete All Secure Jobs</b>';

    return xerox;
  }
  exit(0); # we don't know this printer
}

# @brief Builds the base hardware CPE for Xerox printer
#
# @param model The detected model on which the CPE will be based on
#
# @return A string with the built CPE. By default this will be "cpe:/h:xerox:printer" if no other
#         model matches
#
function build_xerox_cpe(model) {

  local_var model, cpe, m;

  cpe = "cpe:/h";
  model = chomp(model);

  if("WorkCentre" >< model) {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
     return cpe + ':xerox:workcentre';
    } else {
      return cpe + ':xerox:workcentre_' + m[1];
    }
  }

  else if("Phaser" >< model) {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ':xerox:phaser';
    } else {
      return cpe + ':xerox:phaser_' + m[1];
    }
  }

  else if("ColorQube" >< model) {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ':xerox:colorqube';
    } else {
      return cpe + ':xerox:colorqube_' + m[1];
    }
  }

  else if("AltaLink" >< model) {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ':xerox:altalink';
    } else {
      return cpe + ':xerox:altalink_' + m[1];
    }
  }

  else if("ApeosPort" >< model) {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ':xerox:apeosport';
    } else {
      return cpe + ':xerox:apeosport_' + m[1];
    }
  }

  else if("DocuPrint" >< model) {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ':xerox:docuprint';
    } else {
      return cpe + ':xerox:docuprint_' + m[1];
    }
  }

  else if("DocuCentre" >< model) {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ':xerox:docucentre';
    } else {
      return cpe + ':xerox:docucentre_' + m[1];
    }
  }

  else if("DocuColor" >< model) {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ':xerox:docucolor';
    } else {
      return cpe + ':xerox:docucolor_' + m[1];
    }
  }

  else if(model =~ "^[BD]?[0-9]{2,3}") {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[0])) {
      return cpe + ':printer';
    } else {
      return cpe + ':xerox:' + m[0];
    }
  }

  else if(model =~ "^Nuvera") {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ":xerox:nuvera";
    } else {
      return cpe + ":xerox:nuvera_" + m[1];
    }
  }

  else if(model =~ "^Versant") {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ":xerox:versant";
    } else {
      return cpe + ":xerox:versant_" + m[1];
    }
  }

  else if(model =~ "^VersaLink") {

    model = tolower(model);
    m = split(model, sep:" ", keep:FALSE);

    if(isnull(m[1])) {
      return cpe + ":xerox:versalink";
    } else {
      return cpe + ":xerox:versalink_" + m[1];
    }
  }

  return "cpe:/h:xerox:printer";
}

function xerox_set_cookie( url, port ) {

  local_var url, port;

  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("Set-Cookie:" >!< buf) return FALSE;

  co = eregmatch(pattern:"Set-Cookie: ([^; ]+)", string:buf);
  if(!isnull(co[1])) {
    xerox_cookie = co[1];
    return TRUE;
  }
  return FALSE;
}

function xerox_error_exit(buf) {

  if(!buf || ereg(pattern:"HTTP/1.(0|1) (404|500)", string:buf))exit(0);

  return TRUE;
}
