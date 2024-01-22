# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893075");
  script_cve_id("CVE-2022-2787");
  script_tag(name:"creation_date", value:"2022-08-19 01:00:20 +0000 (Fri, 19 Aug 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-01 19:33:00 +0000 (Thu, 01 Sep 2022)");

  script_name("Debian: Security Advisory (DLA-3075-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3075-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3075-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/schroot");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'schroot' package(s) announced via the DLA-3075-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Julian Gilbey discovered that schroot, a tool allowing users to execute commands in a chroot environment, had too permissive rules on chroot or session names, allowing a denial of service on the schroot service for all users that may start a schroot session.

Note that existing chroots and sessions are checked during upgrade, and an upgrade is aborted if any future invalid name is detected.

Problematic session and chroots can be checked before upgrading with the following command:

schroot --list --all <pipe> LC_ALL=C grep -vE '^[a-z]+:[a-zA-Z0-9][a-zA-Z0-9_.-]*$'

See for instructions on how to resolve such a situation.

For Debian 10 buster, this problem has been fixed in version 1.6.10-6+deb10u1.

We recommend that you upgrade your schroot packages.

For the detailed security status of schroot please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'schroot' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"schroot", ver:"1.6.10-6+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"schroot-common", ver:"1.6.10-6+deb10u1", rls:"DEB10"))) {
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
