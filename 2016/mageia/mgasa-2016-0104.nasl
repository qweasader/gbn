# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131261");
  script_cve_id("CVE-2015-1191");
  script_tag(name:"creation_date", value:"2016-03-10 05:17:42 +0000 (Thu, 10 Mar 2016)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2016-0104)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0104");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0104.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17895");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2016-03/msg00013.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pigz' package(s) announced via the MGASA-2016-0104 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple directory traversal vulnerabilities in pigz 2.3.1 allow remote
attackers to write to arbitrary files via a full pathname or .. (dot dot)
in an archive (CVE-2015-1191).");

  script_tag(name:"affected", value:"'pigz' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"pigz", rpm:"pigz~2.3.1~3.1.mga5", rls:"MAGEIA5"))) {
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
