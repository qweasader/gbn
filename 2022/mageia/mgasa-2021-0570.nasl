# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0570");
  script_cve_id("CVE-2021-44540", "CVE-2021-44541", "CVE-2021-44542", "CVE-2021-44543");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-29 19:13:00 +0000 (Wed, 29 Dec 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0570)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0570");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0570.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29745");
  script_xref(name:"URL", value:"http://www.privoxy.org/announce.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'privoxy' package(s) announced via the MGASA-2021-0570 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated privoxy packages fix security vulnerabilities:

A security issue has been found in Privoxy before version 3.0.33.
get_url_spec_param() did not free memory of compiled pattern spec
before bailing (CVE-2021-44540).

A security issue has been found in Privoxy before version 3.0.33.
process_encrypted_request_headers() did not free header memory when
failing to get the request destination (CVE-2021-44541).

A security issue has been found in Privoxy before version 3.0.33.
send_http_request() leaked memory when handling errors (CVE-2021-44542).

A security issue has been found in Privoxy before version 3.0.33.
cgi_error_no_template() did not encode the template name, which could
lead to cross-site scripting when Privoxy is configured to service, serve the
user-manual itself (CVE-2021-44543).");

  script_tag(name:"affected", value:"'privoxy' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"privoxy", rpm:"privoxy~3.0.32~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
