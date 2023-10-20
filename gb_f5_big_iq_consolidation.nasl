# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143118");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2019-11-13 06:37:37 +0000 (Wed, 13 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("F5 BIG-IQ Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of F5 BIG-IQ detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_f5_big_iq_http_detect.nasl", "gb_f5_big_iq_ssh_login_detect.nasl");
  script_mandatory_keys("f5/big_iq/detected");

  script_xref(name:"URL", value:"https://www.f5.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("version_func.inc");

SCRIPT_DESC = "F5 BIG-IQ Detection Consolidation";

if (!get_kb_item("f5/big_iq/detected"))
  exit(0);

detected_version = "unknown";
detected_build = "unknown";

foreach source (make_list("ssh-login", "http")) {
  version_list = get_kb_list("f5/big_iq/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("f5/big_iq/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "f5/big_iq/build", value: detected_build);
      break;
    }
  }
}

app_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:f5:big-iq_centralized_management:");
if (!app_cpe)
  app_cpe = "cpe:/a:f5:big-iq_centralized_management";
hw_cpe = "cpe:/h:f5:big-iq";

location = "/";

if (ssh_ports = get_kb_list("f5/big_iq/ssh-login/port")) {
  foreach port (ssh_ports) {
    extra += "SSH login on port " + port + '/tcp\n';

    register_product(cpe: app_cpe, location: location, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

if (http_ports = get_kb_list("f5/big_iq/http/port")) {
  foreach port (http_ports) {
    concluded = get_kb_item("f5/big_iq/http/" + port + "/concluded");
    concUrl = get_kb_item("f5/big_iq/http/" + port + "/concUrl");
    extra += "HTTP(s) on port " + port + '/tcp\n';
    if (concluded) {
      if (concUrl)
        extra += "  Concluded from version/product identification location: " + concUrl + '\n';

      extra += "  Concluded from version/product identification result: " + concluded + '\n';
    }

    register_product(cpe: app_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

# https://my.f5.com/manage/s/article/K14377 had the following in the past:
# 6.0.0 - 7.1.0 -> CentOS 6.6
# and now includes:
# 8.0.0 - 8.3.0 -> CentOS 7.3
#
# https://my.f5.com/manage/s/article/K121 had the following in the past:
# BIG-IQ Centralized Management 4.6.0 - 7.1.0 -> CentOS Linux
# and now includes:
# BIG-IQ Centralized Management 7.0.0 - 8.3.0 -> CentOS Linux
#
# If this needs to be cross-checked pages like "archive.org" can be used. Make sure to use the older
# support.f5.com/csp/article/Kxxx URLs for this as the my.f5.com URLs are probably not archived for
# 2022 and earlier.
#
if (version_in_range(version: detected_version, test_version: "8.0.0", test_version2: "8.3.0"))
  os_register_and_report(os: "CentOS", version: "7.3", cpe: "cpe:/o:centos:centos", desc: SCRIPT_DESC, runs_key: "unixoide");

else if (version_in_range(version: detected_version, test_version: "6.0.0", test_version2: "7.1.0"))
  os_register_and_report(os: "CentOS", version: "6.6", cpe: "cpe:/o:centos:centos", desc: SCRIPT_DESC, runs_key: "unixoide");

else if (version_in_range(version: detected_version, test_version: "4.6.0", test_version2: "7.1.0"))
  os_register_and_report(os: "CentOS", cpe: "cpe:/o:centos:centos", desc: SCRIPT_DESC, runs_key: "unixoide");

else
  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: SCRIPT_DESC, runs_key: "unixoide");

report = build_detection_report(app: "F5 BIG-IQ", version: detected_version, install: location, cpe: app_cpe,
                                extra: "Build: " + detected_build);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
