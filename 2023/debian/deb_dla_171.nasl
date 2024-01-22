# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.171");
  script_cve_id("CVE-2015-1782");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-171-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-171-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-171-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh2' package(s) announced via the DLA-171-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mariusz Ziulek reported that libssh2, a SSH2 client-side library, was reading and using the SSH_MSG_KEXINIT packet without doing sufficient range checks when negotiating a new SSH session with a remote server. A malicious attacker could man in the middle a real server and cause a client using the libssh2 library to crash (denial of service) or otherwise read and use unintended memory areas in this process.

For Debian 6 Squeeze, these issues have been fixed in libssh2 version 1.2.6-1+deb6u1");

  script_tag(name:"affected", value:"'libssh2' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssh2-1", ver:"1.2.6-1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh2-1-dbg", ver:"1.2.6-1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh2-1-dev", ver:"1.2.6-1+deb6u1", rls:"DEB6"))) {
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
