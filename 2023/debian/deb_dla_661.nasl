# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.661");
  script_cve_id("CVE-2016-8687", "CVE-2016-8688", "CVE-2016-8689");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-17 13:54:11 +0000 (Fri, 17 Feb 2017)");

  script_name("Debian: Security Advisory (DLA-661-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-661-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-661-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libarchive' package(s) announced via the DLA-661-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Agostino Sarubbo of Gentoo discovered several security vulnerabilities in libarchive, a multi-format archive and compression library. An attacker could take advantage of these flaws to cause a buffer overflow or an out of bounds read using a carefully crafted input file.

CVE-2016-8687

Agostino Sarubbo of Gentoo discovered a possible stack-based buffer overflow when printing a filename in bsdtar_expand_char() of util.c.

CVE-2016-8688

Agostino Sarubbo of Gentoo discovered a possible out of bounds read when parsing multiple long lines in bid_entry() and detect_form() of archive_read_support_format_mtree.c.

CVE-2016-8689

Agostino Sarubbo of Gentoo discovered a possible heap-based buffer overflow when reading corrupted 7z files in read_Header() of archive_read_support_format_7zip.c.

For Debian 7 Wheezy, these problems have been fixed in version 3.0.4-3+wheezy5.

We recommend that you upgrade your libarchive packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libarchive' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"bsdcpio", ver:"3.0.4-3+wheezy5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsdtar", ver:"3.0.4-3+wheezy5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"3.0.4-3+wheezy5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive12", ver:"3.0.4-3+wheezy5", rls:"DEB7"))) {
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
