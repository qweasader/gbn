# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0245");
  script_cve_id("CVE-2014-3755", "CVE-2014-3756");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0245)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0245");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0245.html");
  script_xref(name:"URL", value:"http://mumble.info/security/Mumble-SA-2014-005.txt");
  script_xref(name:"URL", value:"http://mumble.info/security/Mumble-SA-2014-006.txt");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/05/15/4");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13382");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mumble' package(s) announced via the MGASA-2014-0245 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated mumble packages fix security vulnerabilities:

In Mumble before 1.2.6, the Mumble client is vulnerable to a Denial of
Service attack when rendering crafted SVG files that contain references to
files on the local computer, due to an issue in Qt's SVG renderer module.
This issue can be triggered remotely by an entity participating in a Mumble
voice chat, using text messages, channel comments, user comments and user
textures/avatars (CVE-2014-3755).

In Mumble before 1.2.6, The Mumble client did not properly HTML-escape some
external strings before using them in a rich-text (HTML) context. In some
situations, this could be abused to perform a Denial of Service attack on a
Mumble client by causing it to load external files via the HTML
(CVE-2014-3756).");

  script_tag(name:"affected", value:"'mumble' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"mumble", rpm:"mumble~1.2.3~10.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-11x", rpm:"mumble-11x~1.2.3~10.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-plugins", rpm:"mumble-plugins~1.2.3~10.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-protocol-kde4", rpm:"mumble-protocol-kde4~1.2.3~10.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server", rpm:"mumble-server~1.2.3~10.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"mumble", rpm:"mumble~1.2.3~14.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-11x", rpm:"mumble-11x~1.2.3~14.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-plugins", rpm:"mumble-plugins~1.2.3~14.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-protocol-kde4", rpm:"mumble-protocol-kde4~1.2.3~14.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mumble-server", rpm:"mumble-server~1.2.3~14.1.mga4", rls:"MAGEIA4"))) {
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
