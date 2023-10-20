# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58578");
  script_cve_id("CVE-2007-2231");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1359)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1359");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1359");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1359");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DSA-1359 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that dovecot, a secure mail server that supports mbox and maildir mailboxes, when configured to use non-system-user spools and compressed folders, may allow directory traversal in mailbox names.

For the old stable distribution (sarge), this problem was not present.

For the stable distribution (etch), this problem has been fixed in version 1.0.rc15-2etch1.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you upgrade your dovecot package.");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"1.0.rc15-2etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1.0.rc15-2etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1.0.rc15-2etch1", rls:"DEB4"))) {
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
