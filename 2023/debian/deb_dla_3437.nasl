# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3437");
  script_cve_id("CVE-2019-14889", "CVE-2023-1667");
  script_tag(name:"creation_date", value:"2023-05-30 04:22:27 +0000 (Tue, 30 May 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-01 20:16:00 +0000 (Wed, 01 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-3437)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3437");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3437");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libssh");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh' package(s) announced via the DLA-3437 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues have been discovered in libssh, a tiny C SSH library, which may allows an remote authenticated user to cause a denial of service or inject arbitrary commands.

CVE-2019-14889

A flaw was found with the libssh API function ssh_scp_new() in versions before 0.9.3 and before 0.8.8. When the libssh SCP client connects to a server, the scp command, which includes a user-provided path, is executed on the server-side. In case the library is used in a way where users can influence the third parameter of the function, it would become possible for an attacker to inject arbitrary commands, leading to a compromise of the remote target.

CVE-2023-1667

A NULL pointer dereference was found In libssh during re-keying with algorithm guessing. This issue may allow an authenticated client to cause a denial of service.

For Debian 10 buster, these problems have been fixed in version 0.8.7-1+deb10u2.

We recommend that you upgrade your libssh packages.

For the detailed security status of libssh please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libssh' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssh-doc", ver:"0.8.7-1+deb10u2", rls:"DEB10"))) {
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
