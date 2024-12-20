# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0450");
  script_cve_id("CVE-2014-7273", "CVE-2014-7274", "CVE-2014-7275");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0450)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0450");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0450.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2014-10/msg00029.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14245");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'getmail' package(s) announced via the MGASA-2014-0450 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The IMAP-over-SSL implementation in getmail 4.0.0 through 4.43.0 does not
verify X.509 certificates from SSL servers, which allows man-in-the-middle
attackers to spoof IMAP servers and obtain sensitive information via a crafted
certificate (CVE-2014-7273).

The IMAP-over-SSL implementation in getmail 4.44.0 does not verify that the
server hostname matches a domain name in the subject's Common Name (CN) field
of the X.509 certificate, which allows man-in-the-middle attackers to spoof
IMAP servers and obtain sensitive information via a crafted certificate from
a recognized Certification Authority (CVE-2014-7274).

The POP3-over-SSL implementation in getmail 4.0.0 through 4.44.0 does not
verify X.509 certificates from SSL servers, which allows man-in-the-middle
attackers to spoof POP3 servers and obtain sensitive information via a
crafted certificate (CVE-2014-7275).");

  script_tag(name:"affected", value:"'getmail' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"getmail", rpm:"getmail~4.46.0~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"getmail", rpm:"getmail~4.46.0~1.mga4", rls:"MAGEIA4"))) {
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
