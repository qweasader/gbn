# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0297");
  script_cve_id("CVE-2013-4287", "CVE-2013-4363");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0297)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0297");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0297.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11276");
  script_xref(name:"URL", value:"http://blog.rubygems.org/2013/09/09/CVE-2013-4287.html");
  script_xref(name:"URL", value:"http://blog.rubygems.org/2013/09/24/CVE-2013-4363.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-September/115886.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4287");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-RubyGems' package(s) announced via the MGASA-2013-0297 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ruby-RubyGems package fixes security vulnerability:

RubyGems validates versions with a regular expression that is vulnerable to
denial of service due to a backtracking regular expression. For specially
crafted RubyGems versions attackers can cause denial of service through CPU
consumption (CVE-2013-4287, CVE-2013-4363).");

  script_tag(name:"affected", value:"'ruby-RubyGems' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"ruby-RubyGems", rpm:"ruby-RubyGems~1.8.27~1.mga3", rls:"MAGEIA3"))) {
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
