# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53404");
  script_cve_id("CVE-2002-0391");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-142)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-142");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/dsa-142");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-142");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DSA-142 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow bug has been discovered in the RPC library used by the OpenAFS database server, which is derived from the SunRPC library. This bug could be exploited to crash certain OpenAFS servers (volserver, vlserver, ptserver, buserver) or to obtain unauthorized root access to a host running one of these processes. No exploits are known to exist yet.

This problem has been fixed in version 1.2.3final2-6 for the current stable distribution (woody) and in version 1.2.6-1 for the unstable distribution (sid). Debian 2.2 (potato) is not affected since it doesn't contain OpenAFS packages.

OpenAFS is only available for the architectures alpha, i386, powerpc, s390, sparc. Hence, we only provide fixed packages for these architectures.

We recommend that you upgrade your openafs packages.");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.2.3final2-6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-client", ver:"1.2.3final2-6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.2.3final2-6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.2.3final2-6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.2.3final2-6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.2.3final2-6", rls:"DEB3.0"))) {
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
