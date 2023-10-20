# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2004.208.01");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2004-208-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-208-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.397947");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'alternate' package(s) announced via the SSA:2004-208-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was pointed out that the new Samba packages for Slackware 10.0
(and -current) have a dependency on libattr.so that wasn't in the previous
packages. Since it's not the intent to introduce new requirements in
security patches (especially for stable versions), an alternate version
of the samba package is being made available that does not require
libattr.so.

The original samba-3.0.5-i486-1.tgz package for Slackware 10.0 will also
remain in the patches directory (at least for now, since it was just
referenced in a security advisory and the URL to it should remain working),
and because the original package works fine if the xfsprogs package (which
contains libattr) is installed. If you're running a full installation or
have xfsprogs installed, you do not need to update samba again.


Here are the details from the Slackware 10.0 ChangeLog:
+--------------------------+
Mon Jul 26 14:10:01 PDT 2004
patches/packages/samba-3.0.5-i486-2.tgz:
 Rebuilt using --with-acl-support=no to avoid a dependency on libattr
 (found in the xfsprogs package). Thanks to Fredrik, Naresh Donti,
 and Dimitar Katerinski for pointing this out. It wasn't intentional
 (only the version number changed in the build script).
+--------------------------+");

  script_tag(name:"affected", value:"'alternate' package(s) on Slackware 10.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK10.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"3.0.5-i486-2", rls:"SLK10.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"3.0.5-i486-2", rls:"SLKcurrent"))) {
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
