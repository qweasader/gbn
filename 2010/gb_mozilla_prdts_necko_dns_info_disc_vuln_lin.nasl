# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800456");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-4629");
  script_name("Mozilla Products Necko DNS Information Disclosure Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_lin.nasl", "gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");

  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=492196");
  script_xref(name:"URL", value:"https://bug492196.bugzilla.mozilla.org/attachment.cgi?id=377824");
  script_xref(name:"URL", value:"https://secure.grepular.com/DNS_Prefetch_Exposure_on_Thunderbird_and_Webmail");

  script_tag(name:"impact", value:"Successful exploitation will let the attackers obtain the network location of
  the applications user by logging DNS requests.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version 3.0.1 and
  Seamonkey with Mozilla Necko version 1.9.0 and prior on Linux.");

  script_tag(name:"insight", value:"The flaw exists while DNS prefetching, when the app type is 'APP_TYPE_MAIL'
  or 'APP_TYPE_EDITOR'.");

  script_tag(name:"summary", value:"Thunderbird/Seamonkey is prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"Apply the referenced updates or upgrade to Mozilla Necko version 1.9.1.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

fpVer = get_kb_item("Thunderbird/Linux/Ver");
if(fpVer){
  if(version_is_less_equal(version:fpVer, test_version:"3.0.1")){
    report = report_fixed_ver(installed_version:fpVer, fixed_version:"3.0.2");
    security_message(port:0, data:report);
    exit(0);
  }
}

seaVer = get_kb_item("Seamonkey/Linux/Ver");
if(!seaVer){
  exit(0);
}

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("rv:[0-9.].\\+");

modName = ssh_find_file(file_name:"/libnecko\.so$", useregex:TRUE, sock:sock);
foreach binaryName (modName) {

  binaryName = chomp(binaryName);
  if(!binaryName) continue;

  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;

  seaVer = ssh_get_bin_version(full_prog_name:"grep", version_argv:arg, ver_pattern:"([0-9.]+)", sock:sock);
  if(seaVer[1]){
    if(version_is_less(version:seaVer[1], test_version:"1.9.1")){
      report = report_fixed_ver(installed_version:seaVer[1], fixed_version:"1.9.1", install_path:binaryName);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);
