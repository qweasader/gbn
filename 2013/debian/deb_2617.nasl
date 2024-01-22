# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702617");
  script_cve_id("CVE-2013-0213", "CVE-2013-0214");
  script_tag(name:"creation_date", value:"2013-02-01 23:00:00 +0000 (Fri, 01 Feb 2013)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2617-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2617-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2617");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-2617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn had reported two vulnerabilities in Samba, a popular cross-platform network file and printer sharing suite. In particular, these vulnerabilities affect to SWAT, the Samba Web Administration Tool.

CVE-2013-0213: Clickjacking issue in SWAT An attacker can integrate a SWAT page into a malicious web page via a frame or iframe and then overlaid by other content. If an authenticated valid user interacts with this malicious web page, she might perform unintended changes in the Samba settings.

CVE-2013-0214: Potential Cross-site request forgery An attacker can persuade a valid SWAT user, who is logged in as root, to click in a malicious link and trigger arbitrary unintended changes in the Samba settings. In order to be vulnerable, the attacker needs to know the victim's password.

For the stable distribution (squeeze), these problems have been fixed in version 2:3.5.6~dfsg-3squeeze9.

For the testing distribution (wheezy), these problems have been fixed in version 2:3.6.6-5.

For the unstable distribution (sid), these problems have been fixed in version 2:3.6.6-5.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient0", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"swat", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"2:3.5.6~dfsg-3squeeze9", rls:"DEB6"))) {
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
