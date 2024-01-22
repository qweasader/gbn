# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704257");
  script_cve_id("CVE-2018-10906");
  script_tag(name:"creation_date", value:"2018-07-27 22:00:00 +0000 (Fri, 27 Jul 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4257-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4257-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4257-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4257");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/fuse");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fuse' package(s) announced via the DSA-4257-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that FUSE, a Filesystem in USErspace, allows the bypass of the user_allow_other restriction when SELinux is active (including in permissive mode). A local user can take advantage of this flaw in the fusermount utility to bypass the system configuration and mount a FUSE filesystem with the allow_other mount option.

For the stable distribution (stretch), this problem has been fixed in version 2.9.7-1+deb9u1.

We recommend that you upgrade your fuse packages.

For the detailed security status of fuse please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'fuse' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"fuse", ver:"2.9.7-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-dbg", ver:"2.9.7-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-udeb", ver:"2.9.7-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfuse-dev", ver:"2.9.7-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfuse2", ver:"2.9.7-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfuse2-udeb", ver:"2.9.7-1+deb9u1", rls:"DEB9"))) {
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
