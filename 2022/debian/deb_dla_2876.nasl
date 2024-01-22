# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892876");
  script_cve_id("CVE-2017-17087", "CVE-2019-20807", "CVE-2021-3778", "CVE-2021-3796");
  script_tag(name:"creation_date", value:"2022-01-11 02:00:08 +0000 (Tue, 11 Jan 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 19:43:00 +0000 (Tue, 12 Oct 2021)");

  script_name("Debian: Security Advisory (DLA-2876-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2876-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2876-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/vim");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vim' package(s) announced via the DLA-2876-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been discovered in vim: an enhanced vi text editor:

CVE-2017-17087

fileio.c in Vim sets the group ownership of a .swp file to the editor's primary group (which may be different from the group ownership of the original file), which allows local users to obtain sensitive information by leveraging an applicable group membership.

CVE-2019-20807

Users can circumvent the rvim restricted mode and execute arbitrary OS commands via scripting interfaces (e.g., Python, Ruby, or Lua).

CVE-2021-3778

Heap-based Buffer Overflow with invalid utf-8 character was detected in regexp_nfa.c.

CVE-2021-3796

Heap Use-After-Free memory error was detected in normal.c. A successful exploitation may lead to code execution.

For Debian 9 stretch, these problems have been fixed in version 2:8.0.0197-4+deb9u4.

We recommend that you upgrade your vim packages.

For the detailed security status of vim please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'vim' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-common", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-doc", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gnome", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gui-common", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-runtime", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
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
