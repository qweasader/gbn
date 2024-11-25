# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.383");
  script_cve_id("CVE-2015-8614");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-13 18:03:35 +0000 (Wed, 13 Apr 2016)");

  script_name("Debian: Security Advisory (DLA-383-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-383-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-383-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'claws-mail' package(s) announced via the DLA-383-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"'DrWhax' of the Tails project reported that Claws Mail is missing range checks in some text conversion functions. A remote attacker could exploit this to run arbitrary code under the account of a user that receives a message from them using Claws Mail.

CVE-2015-8614

There were no checks on the output length for conversions between JIS (ISO-2022-JP) and EUC-JP, between JIS and UTF-8, and from Shift_JIS to EUC-JP.

CVE-2015-8708

The original fix for CVE-2015-8614 was incomplete.

For the oldoldstable distribution (squeeze), these problems have been fixed in version 3.7.6-4+squeeze2.

For the oldstable distribution (wheezy) and the stable distribution (jessie), this will be fixed soon. These versions were built with hardening features that make this issue harder to exploit.");

  script_tag(name:"affected", value:"'claws-mail' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-bogofilter", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-dbg", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-doc", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-i18n", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-pgpinline", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-pgpmime", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-plugins", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-smime-plugin", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-spamassassin", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-tools", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"claws-mail-trayicon", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclaws-mail-dev", ver:"3.7.6-4+squeeze2", rls:"DEB6"))) {
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
