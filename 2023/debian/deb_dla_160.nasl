# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.160");
  script_cve_id("CVE-2014-0106", "CVE-2014-9680");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:29:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DLA-160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-160-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-160-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sudo' package(s) announced via the DLA-160-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the CVEs described below.

CVE-2014-0106

Todd C. Miller reported that if the env_reset option is disabled in the sudoers file, the env_delete option is not correctly applied to environment variables specified on the command line. A malicious user with sudo permissions may be able to run arbitrary commands with elevated privileges by manipulating the environment of a command the user is legitimately allowed to run.

CVE-2014-9680

Jakub Wilk reported that sudo preserves the TZ variable from a user's environment without any sanitization. A user with sudo access may take advantage of this to exploit bugs in the C library functions which parse the TZ environment variable or to open files that the user would not otherwise be able to open. The latter could potentially cause changes in system behavior when reading certain device special files or cause the program run via sudo to block.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.7.4p4-2.squeeze.5.

For the stable distribution (wheezy), they have been fixed in version 1.8.5p2-1+nmu2.

We recommend that you upgrade your sudo packages.");

  script_tag(name:"affected", value:"'sudo' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.7.4p4-2.squeeze.5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.7.4p4-2.squeeze.5", rls:"DEB6"))) {
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
